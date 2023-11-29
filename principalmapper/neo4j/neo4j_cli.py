"""Code to implement the CLI interface to the AWS Organizations (OrganizationTrees) component of Principal Mapper"""

#  Copyright (c) NCC Group and Erik Steringer 2021. This file is part of Principal Mapper.
#
#      Principal Mapper is free software: you can redistribute it and/or modify
#      it under the terms of the GNU Affero General Public License as published by
#      the Free Software Foundation, either version 3 of the License, or
#      (at your option) any later version.
#
#      Principal Mapper is distributed in the hope that it will be useful,
#      but WITHOUT ANY WARRANTY; without even the implied warranty of
#      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#      GNU Affero General Public License for more details.
#
#      You should have received a copy of the GNU Affero General Public License
#      along with Principal Mapper.  If not, see <https://www.gnu.org/licenses/>.

import json
import logging
import os
import os.path
import re
from argparse import ArgumentParser, Namespace
from pathlib import Path
from typing import List

from principalmapper.common import OrganizationTree, OrganizationNode, Graph, OrganizationAccount, Policy, Edge
from principalmapper.graphing.cross_account_edges import get_edges_between_graphs
from principalmapper.graphing.gathering import get_organizations_data
from principalmapper.querying.query_orgs import produce_scp_list
from principalmapper.util import botocore_tools
from principalmapper.graphing import graph_actions
from principalmapper.util.storage import get_storage_root
from principalmapper.neo4j.neo4j_driver import load_graph_to_neo4j, load_cross_account_edges_to_neo4j, load_external_edges_to_neo4j, load_identitycentre_to_neo4j

from principalmapper.querying.presets import externalaccess
from principalmapper.util.arns import get_resource, validate_arn, get_account_id, is_valid_aws_account_id


logger = logging.getLogger(__name__)


def provide_arguments(parser: ArgumentParser):
    """Given a parser object (which should be a subparser), add arguments to provide a CLI interface to the
    organizations component of Principal Mapper.
    """

    neo4j_subparser = parser.add_subparsers(
        title='neo4j_subcommand',
        description='The subcommand to use in the organizations component of Principal Mapper',
        dest='picked_neo4j_cmd',
        help='Select an organizations subcommand to execute'
    )

    load_parser = neo4j_subparser.add_parser(
        'load',
        description='Loads all graphed accounts within AWS Organizations data into neo4j',
        help='Loads all graphed accounts within AWS Organizations data into neo4j',
    )
    load_parser.add_argument(
        '--org',
        help='The ID of the organization to update'
    )

    add_cross_account_access_parser = neo4j_subparser.add_parser(
        'add_cross_account_access',
        description='Updates the data stored in neo4j',
        help='Updates the data stored in neo4jn',
    )
    add_cross_account_access_parser.add_argument(
        '--org',
        help='The ID of the organization to update'
    )

    identitycentre_parser = neo4j_subparser.add_parser(
        'identitycentre',
        description='Updates the data stored in neo4j',
        help='Updates the data stored in neo4jn',
    )
    identitycentre_parser.add_argument(
        '--org',
        help='The ID of the organization to update'
    )

    external_access_parser = neo4j_subparser.add_parser(
        'external_access',
        description='Updates the data stored in neo4j',
        help='Updates the data stored in neo4jn',
    )
    external_access_parser.add_argument(
        '--org',
        help='The ID of the organization to update'
    )

    



def process_arguments(parsed_args: Namespace):
    """Given a namespace object generated from parsing args, perform the appropriate tasks. Returns an int
    matching expectations set by /usr/include/sysexits.h for command-line utilities."""


    # new args for handling AWS Organizations
    if parsed_args.picked_neo4j_cmd == 'load':
        logger.debug('Called load subcommand for neo4j')

        # filter the args first
        if parsed_args.account is None and parsed_args.org is None:
            print('Please specify either an account ID or and Org ID whose data should be updated in Neo4j')
            return 64
        
        if parsed_args.account and parsed_args.org:
            print('Please specify either an account ID or and Org ID whose data should be updated in Neo4j, not both.')
            return 64
        
        graph_objs = []
        
        if parsed_args.org:
            # pull the existing data from disk
            org_filepath = os.path.join(get_storage_root(), parsed_args.org)
            org_tree = OrganizationTree.create_from_dir(org_filepath)
        
            for account in org_tree.accounts:
                graph_objs.append(graph_actions.get_existing_graph(session=None,account=account))
                print(1)
        else:
            graph_objs.append(graph_actions.get_existing_graph(session=None,account=account))
            print(2)

        if not graph_objs:
            print('No graphs were loaded. Please check that the account data has already been ingested before running this command')
            return 64

        for graph_obj in graph_objs:
            # Load the data into Neo4j
            if not graph_obj:
                continue
            load_graph_to_neo4j(graph_obj)
            print(3)

        if org_tree.edge_list:
            load_cross_account_edges_to_neo4j(org_tree.edge_list)

            external_edges,external_accounts = _generate_external_edges(parsed_args)
            load_external_edges_to_neo4j(external_edges,external_accounts)

        if org_tree.identity_stores:
            load_identitycentre_to_neo4j(org_tree)


    elif parsed_args.picked_neo4j_cmd == 'add_cross_account_access':
        logger.debug('Called add_cross_account_access subcommand for neo4j')

        # filter the args first
        if parsed_args.org is None:
            print('Please specify an Org ID for which cross account access should be loaded into Neo4j')
            return 64
        
        # pull the existing data from disk
        org_filepath = os.path.join(get_storage_root(), parsed_args.org)
        org_tree = OrganizationTree.create_from_dir(org_filepath)
        
        if org_tree.edge_list:
            load_cross_account_edges_to_neo4j(org_tree.edge_list)


    elif parsed_args.picked_neo4j_cmd == 'identitycentre':
        logger.debug('Called identitycentre subcommand for neo4j')

        # filter the args first
        if parsed_args.org is None:
            print('Please specify an Org ID for which cross account access should be loaded into Neo4j')
            return 64
        
        # pull the existing data from disk
        org_filepath = os.path.join(get_storage_root(), parsed_args.org)
        org_tree = OrganizationTree.create_from_dir(org_filepath)
        
        if org_tree.identity_stores:
            load_identitycentre_to_neo4j(org_tree)
        else:
            logger.warning("[!] No identity_store.json file found. Please run 'pmapper --profile {AWS Account ID} identitycentre --org {Organisation ID}'.")

    elif parsed_args.picked_neo4j_cmd == 'external_access':
        logger.debug('Called externalaccess subcommand for neo4j')

        # filter the args first
        if parsed_args.org is None:
            print('Please specify an Org ID for which cross account access should be loaded into Neo4j')
            return 64

        external_edges,external_accounts = _generate_external_edges(parsed_args)
        load_external_edges_to_neo4j(external_edges,external_accounts)
            
        
def _generate_external_edges(parsed_args):
    org_filepath = os.path.join(get_storage_root(), parsed_args.org)
    org_tree = OrganizationTree.create_from_dir(org_filepath)

    graph_objs = []
    for account in org_tree.accounts:
        try:
            potential_path = os.path.join(get_storage_root(), account)
            logger.debug('Trying to load a Graph from {}'.format(potential_path))
            graph_obj = Graph.create_graph_from_local_disk(potential_path)
            graph_objs.append(graph_obj)
        except Exception as ex:
            logger.warning('Unable to load a Graph object for account {}, possibly because it is not mapped yet. '
                            'Please map all accounts and then update the Organization Tree '
                            '(`pmapper orgs update --org $ORG_ID`).'.format(account))
            logger.debug(str(ex))

    # Get a unique list of external accounts
    external_accounts = set()
    # Get a list of external edges
    external_edges = []
    for graph_obj in graph_objs:
        external_access_nodes = externalaccess.determine_external_access(graph_obj, include_fedenerated = False)
        
        for node in external_access_nodes:
            for principal in node.allowed_external_access:
                if is_valid_aws_account_id(principal):
                    # Got an account ID
                    account_id = principal
                elif validate_arn(principal):
                    # Got a user, role, or root of account. Extract the account id
                    account_id = get_account_id(principal)
                else:
                    pass # Check why we got here

                # Check if the account id is within the Org
                if account_id in org_tree.accounts:
                    continue
                else:
                    external_edges.append(Edge(
                        source=principal,
                        destination=node.arn,
                        reason='can call sts:AssumeRole to access',
                        short_reason='STS'
                    ))
                    external_accounts.add(account_id)
    return external_edges,external_accounts


def _map_account_ou_paths(org_tree: OrganizationTree) -> dict:
    """Given an OrganizationTree, create a map from account -> ou path"""
    result = {}

    def _traverse(org_node: OrganizationNode, base_string: str):
        full_node_str = '{}{}/'.format(base_string, org_node.ou_id)
        for account in org_node.accounts:
            result[account] = full_node_str
        for child_node in org_node.child_nodes:
            _traverse(child_node, full_node_str)

    for root_ou in org_tree.root_ous:
        _traverse(root_ou, '{}/'.format(org_tree.org_id))

    return result


def _update_accounts_with_ou_path_map(org_id: str, account_ou_map: dict, root_dir: str):
    """Given a map produced by `_map_account_ou_paths` go through the available on-disk graphs and update metadata
    appropriately."""

    for account, ou_path in account_ou_map.items():
        potential_path = os.path.join(root_dir, account.account_id, 'metadata.json')
        if os.path.exists(os.path.join(potential_path)):
            try:
                fd = open(potential_path, 'r')
                metadata = json.load(fd)
                new_org_data = {
                    'org-id': org_id,
                    'org-path': ou_path
                }
                logger.debug('Updating {} with org data: {}'.format(account.account_id, new_org_data))
                metadata['org-id'] = org_id
                metadata['org-path'] = ou_path
                fd.close()

                fd = open(potential_path, 'w')
                json.dump(metadata, fd, indent=4)
            except IOError as ex:
                logger.debug('IOError when reading/writing metadata of {}: {}'.format(account.account_id, str(ex)))
                continue
        else:
            logger.debug(
                'Account {} of organization {} does not have a Graph. You will need to update the '
                'organization data at a later point (`pmapper orgs update --org $ORG_ID`).'.format(account.account_id, org_id)
            )  # warning gets thrown up by caller, no need to reiterate

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

from principalmapper.common import OrganizationTree, OrganizationNode, Graph, OrganizationAccount, Policy, Node, Edge
from principalmapper.graphing.cross_account_edges import get_edges_between_graphs
from principalmapper.graphing.gathering import get_organizations_data
from principalmapper.querying.query_orgs import produce_scp_list
from principalmapper.util import botocore_tools
from principalmapper.util.storage import get_storage_root

from principalmapper.querying.presets import externalaccess
from principalmapper.util.arns import get_resource, validate_arn, get_account_id, is_valid_aws_account_id


logger = logging.getLogger(__name__)


def provide_arguments(parser: ArgumentParser):
    """Given a parser object (which should be a subparser), add arguments to provide a CLI interface to the
    organizations component of Principal Mapper.
    """

    orgs_subparser = parser.add_subparsers(
        title='orgs_subcommand',
        description='The subcommand to use in the organizations component of Principal Mapper',
        dest='picked_orgs_cmd',
        help='Select an organizations subcommand to execute'
    )

    create_parser = orgs_subparser.add_parser(
        'create',
        description='Creates and stores a OrganizationTree object for a given AWS Organization',
        help='Creates and stores a OrganizationTree object for a given AWS Organization'
    )

    list_parser = orgs_subparser.add_parser(
        'list',
        description='Lists the locally tracked AWS Organizations',
        help='Lists the locally tracked AWS Organizations'
    )

    update_parser = orgs_subparser.add_parser(
        'update',
        description='Updates all graphed accounts with AWS Organizations data - offline operation',
        help='Updates all graphed accounts with AWS Organizations data - offline operation',
    )
    update_parser.add_argument(
        '--org',
        help='The ID of the organization to update',
        required=True
    )

    display_parser = orgs_subparser.add_parser(
        'display',
        description='Gives details on a given AWS Organization',
        help='Gives details on a given AWS Organization'
    )
    display_parser.add_argument(
        '--org',
        help='The ID of the organization to display',
        required=True
    )

    identitycenter_parser = orgs_subparser.add_parser(
        'identitycenter',
        description='Adds Identity Center users to a given AWS Organization',
        help='Adds Identity Center users to a given AWS Organization'
    )
    identitycenter_parser.add_argument(
        '--org',
        help='The ID of the organization to display',
        required=True
    )

    externalaccess_parser = orgs_subparser.add_parser(
        'externalaccess',
        description='Lists the external access for the AWS Organization',
        help='Lists the external access for the AWS Organization'
    )

    externalaccess_parser.add_argument(
        '--org',
        help='The ID of the organization to update',
        required=True
    )


def process_arguments(parsed_args: Namespace):
    """Given a namespace object generated from parsing args, perform the appropriate tasks. Returns an int
    matching expectations set by /usr/include/sysexits.h for command-line utilities."""

    # new args for handling AWS Organizations
    if parsed_args.picked_orgs_cmd == 'create':
        logger.debug('Called create subcommand for organizations')

        # filter the args first
        if parsed_args.account is not None:
            print('Cannot specify offline-mode param `--account` when calling `pmapper orgs create`. If you have '
                  'credentials for a specific account to graph, you can use those credentials similar to how the '
                  'AWS CLI works (environment variables, profiles, EC2 instance metadata). In the case of using '
                  'a profile, use the `--profile [PROFILE]` argument before specifying the `orgs` subcommand.')
            return 64

        # get the botocore session and go to work creating the OrganizationTree obj
        session = botocore_tools.get_session(parsed_args.profile)
        org_tree = get_organizations_data(session)
        logger.info('Generated initial organization data for {}'.format(org_tree.org_id))

        # create the account -> OU path map and apply to all accounts (same as orgs update operation)
        account_ou_map = _map_account_ou_paths(org_tree)
        logger.debug('account_ou_map: {}'.format(account_ou_map))
        _update_accounts_with_ou_path_map(org_tree.org_id, account_ou_map, get_storage_root())
        logger.info('Updated currently stored Graphs with applicable AWS Organizations data')

        # create and cache a list of edges between all the accounts we have data for
        edge_list = []
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

        for graph_obj_a in graph_objs:
            for graph_obj_b in graph_objs:
                if graph_obj_a == graph_obj_b:
                    continue
                graph_a_scps = produce_scp_list(graph_obj_a, org_tree)
                graph_b_scps = produce_scp_list(graph_obj_b, org_tree)
                edge_list.extend(get_edges_between_graphs(graph_obj_a, graph_obj_b, graph_a_scps, graph_b_scps))

        org_tree.edge_list = edge_list
        logger.info('Compiled cross-account edges')

        org_tree.save_organization_to_disk(os.path.join(get_storage_root(), org_tree.org_id))
        logger.info('Stored organization data to disk')

    elif parsed_args.picked_orgs_cmd == 'update':
        # pull the existing data from disk
        org_filepath = os.path.join(get_storage_root(), parsed_args.org)
        org_tree = OrganizationTree.create_from_dir(org_filepath)

        # create the account -> OU path map and apply to all accounts
        account_ou_map = _map_account_ou_paths(org_tree)
        logger.debug('account_ou_map: {}'.format(account_ou_map))
        _update_accounts_with_ou_path_map(org_tree.org_id, account_ou_map, get_storage_root())
        logger.info('Updated currently stored Graphs with applicable AWS Organizations data')

        # create and cache a list of edges between all the accounts we have data for
        edge_list = []
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

        for graph_obj_a in graph_objs:
            for graph_obj_b in graph_objs:
                if graph_obj_a == graph_obj_b:
                    continue
                logger.info('Generating edges from {} to {}'.format(graph_obj_a.metadata['account_id'],graph_obj_b.metadata['account_id']))
                graph_a_scps = produce_scp_list(graph_obj_a, org_tree)
                graph_b_scps = produce_scp_list(graph_obj_b, org_tree)
                edge_list.extend(get_edges_between_graphs(graph_obj_a, graph_obj_b, graph_a_scps, graph_b_scps))

        org_tree.edge_list = edge_list
        logger.info('Compiled cross-account edges')

        org_tree.save_organization_to_disk(os.path.join(get_storage_root(), org_tree.org_id))
        logger.info('Stored organization data to disk')

    elif parsed_args.picked_orgs_cmd == 'display':
        # pull the existing data from disk
        org_filepath = os.path.join(get_storage_root(), parsed_args.org)
        org_tree = OrganizationTree.create_from_dir(org_filepath)

        def _print_account(org_account: OrganizationAccount, indent_level: int, inherited_scps: List[Policy]):
            print('{} {}:'.format(' ' * indent_level, org_account.account_id))
            print('{}  Directly Attached SCPs: {}'.format(' ' * indent_level, [x.name for x in org_account.scps]))
            print('{}  Inherited SCPs:         {}'.format(' ' * indent_level, [x.name for x in inherited_scps]))

        def _walk_and_print_ou(org_node: OrganizationNode, indent_level: int, inherited_scps: List[Policy]):
            print('{}"{}" ({}):'.format(' ' * indent_level, org_node.ou_name, org_node.ou_id))
            print('{}  Accounts:'.format(' ' * indent_level))
            for o_account in org_node.accounts:
                _print_account(o_account, indent_level + 2, inherited_scps)
            print('{}  Directly Attached SCPs: {}'.format(' ' * indent_level, [x.name for x in org_node.scps]))
            print('{}  Inherited SCPs:         {}'.format(' ' * indent_level, [x.name for x in inherited_scps]))
            print('{}  Child OUs:'.format(' ' * indent_level))
            for child_node in org_node.child_nodes:
                new_inherited_scps = inherited_scps.copy()
                new_inherited_scps.extend([x for x in org_node.scps if x not in inherited_scps])
                _walk_and_print_ou(child_node, indent_level + 4, new_inherited_scps)

        print('Organization {}:'.format(org_tree.org_id))
        for root_ou in org_tree.root_ous:
            _walk_and_print_ou(root_ou, 0, [])

    elif parsed_args.picked_orgs_cmd == 'list':
        print("Organization IDs:")
        print("---")
        storage_root = Path(get_storage_root())
        account_id_pattern = re.compile(r'o-\w+')
        for direct in storage_root.iterdir():
            if account_id_pattern.search(str(direct)) is not None:
                metadata_file = direct.joinpath(Path('metadata.json'))
                with open(str(metadata_file)) as fd:
                    version = json.load(fd)['pmapper_version']
                print("{} (PMapper Version {})".format(direct.name, version))

    elif parsed_args.picked_orgs_cmd == 'identitycenter':
        logger.debug('Called identitycenter subcommand for organizations')

        # filter the args first
        if parsed_args.org is None:
            print('Please specify an Org ID for which identity center users should be loaded into the Organisation')
            return 64
        
        # Load org
        org_filepath = os.path.join(get_storage_root(), parsed_args.org)
        org_tree = OrganizationTree.create_from_dir(org_filepath)

        # Check that we are in the management account
        session = botocore_tools.get_session(parsed_args.profile)
        stsclient = session.create_client('sts')
        current_account_id = stsclient.get_caller_identity()['Account']  # raises error if it's not workable

        if not current_account_id == org_tree.management_account_id:
            print('Please run this command from the management account')
            return 64
        
        # Load accoung graphs
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
        
        # Fetch users and groups
        # Create nodes for each user and group

        # Create an edge between the users and groups it is a member of
        #   Use: generate_group_membership_edge
        #   Collect edges, and store them

        # For each account in the org:
        #   get the Permission Sets assigned to the account
        #   then get the Account Assignments for each Permission Set assigned to the account
        #   then create an edge between the user/group and the role in the account
        #   Use: generate_account_assignment_edge
        #   Collect edges, and store them
        # 
        pass
        

    if parsed_args.picked_orgs_cmd == 'externalaccess':
        logger.debug('Called externalaccess subcommand for organizations')

        # filter the args first
        if parsed_args.org is None:
            print('Please specify an Org ID for which cross account access should be loaded into the Organisation')
            return 64

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

        account_external_access_map = {}
        for graph_obj in graph_objs:
            current_account_id = graph_obj.metadata['account_id']
            account_external_access_map[current_account_id] = {
                'external_principals': [],
                'internal_principals': []
            }
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
                        account_external_access_map[current_account_id]['internal_principals'].append({
                            'source': node.arn,
                            'destination': principal
                            })
                    else:
                        account_external_access_map[current_account_id]['external_principals'].append({
                            'source': node.arn,
                            'destination': principal
                            })
            for account_id in sorted(account_external_access_map):
                # print external access
                print(f"External access for account {account_id}")
                external_accounts = set()
                for external_principal in account_external_access_map[account_id]['external_principals']:
                    print(f"{external_principal['destination']} -> {external_principal['source']}")
                    principal = external_principal['destination']
                    if is_valid_aws_account_id(principal):
                        # Got an account ID
                        account_id = principal
                    elif validate_arn(principal):
                        # Got a user, role, or root of account. Extract the account id
                        account_id = get_account_id(principal)
                    external_accounts.add(account_id)
                print(external_accounts)
            
            for account_id in sorted(account_external_access_map):
                # print external access
                print(f"Internal access for account {account_id}")
                external_accounts = set()
                for internal_principal in account_external_access_map[account_id]['internal_principals']:
                    print(f"{internal_principal['destination']} -> {internal_principal['source']}")
                    principal = internal_principal['destination']
                    if is_valid_aws_account_id(principal):
                        # Got an account ID
                        account_id = principal
                    elif validate_arn(principal):
                        # Got a user, role, or root of account. Extract the account id
                        account_id = get_account_id(principal)
                    external_accounts.add(account_id)
                print(external_accounts)

    if parsed_args.picked_orgs_cmd == 'externalaccess':
        logger.debug('Called create subcommand for organizations')

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

        account_external_access_map = {}
        for graph_obj in graph_objs:
            current_account_id = graph_obj.metadata['account_id']
            account_external_access_map[current_account_id] = {
                'external_principals': [],
                'internal_principals': []
            }
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
                        account_external_access_map[current_account_id]['internal_principals'].append({
                            'source': node.arn,
                            'destination': principal
                            })
                    else:
                        account_external_access_map[current_account_id]['external_principals'].append({
                            'source': node.arn,
                            'destination': principal
                            })
            for account_id in sorted(account_external_access_map):
                # print external access
                print(f"External access for account {account_id}")
                external_accounts = set()
                for external_principal in account_external_access_map[account_id]['external_principals']:
                    print(f"{external_principal['destination']} -> {external_principal['source']}")
                    principal = external_principal['destination']
                    if is_valid_aws_account_id(principal):
                        # Got an account ID
                        account_id = principal
                    elif validate_arn(principal):
                        # Got a user, role, or root of account. Extract the account id
                        account_id = get_account_id(principal)
                    external_accounts.add(account_id)
                print(external_accounts)
            
            for account_id in sorted(account_external_access_map):
                # print external access
                print(f"Internal access for account {account_id}")
                external_accounts = set()
                for internal_principal in account_external_access_map[account_id]['internal_principals']:
                    print(f"{internal_principal['destination']} -> {internal_principal['source']}")
                    principal = internal_principal['destination']
                    if is_valid_aws_account_id(principal):
                        # Got an account ID
                        account_id = principal
                    elif validate_arn(principal):
                        # Got a user, role, or root of account. Extract the account id
                        account_id = get_account_id(principal)
                    external_accounts.add(account_id)
                print(external_accounts)

    return 0


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


def get_graph_for_account(graph_objs, account_id) -> Graph:
    return next(graph for graph in graph_objs if graph.metadata['account_id'] == account_id)

def get_permission_set_role(graph, permission_set_name) -> Node:
    permission_set_name_prefix = f"AWSReservedSSO_{permission_set_name}_"
    return next(
        node for node in graph.nodes
        if permission_set_name_prefix in node.arn
    )

def generate_group_membership_edge(user_arn, group_arn):
    return Edge(
        source=user_arn, # User arn
        destination=group_arn, # Group arn
        reason="Identity Centre group membership",
        short_reason="group_membership"
    )

def generate_account_assignment_edge(graph_objs, account_id, permission_set_name, source_principal_arn):
    graph = get_graph_for_account(graph_objs,account_id)
    role = get_permission_set_role(graph,permission_set_name)
    return Edge(
        source=source_principal_arn, # User or group arn
        destination=role.arn,
        reason="Identity Centre provisioned access",
        short_reason="identitystore"
    )
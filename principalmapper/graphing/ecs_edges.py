"""Code to identify if a principal in an AWS account can use access to ECS to access other principals."""


#  Copyright (c) NCC Group and Erik Steringer 2022. This file is part of Principal Mapper.
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

import io
import logging
import os
from typing import List, Optional

from principalmapper.common import Edge, Node
from principalmapper.graphing.edge_checker import EdgeChecker
from principalmapper.querying import query_interface
from principalmapper.querying.local_policy_simulation import resource_policy_authorization, ResourcePolicyEvalResult
from principalmapper.util import arns

from multiprocessing import Pool, Manager, cpu_count
from multiprocessing.queues import Queue
from rich.progress import Progress
import time

logger = logging.getLogger(__name__)


class ECSEdgeChecker(EdgeChecker):
    """Class for identifying if ECS can be used by IAM principals to gain access to other IAM principals."""

    def return_edges(self, nodes: List[Node], region_allow_list: Optional[List[str]] = None,
                     region_deny_list: Optional[List[str]] = None, scps: Optional[List[List[dict]]] = None,
                     client_args_map: Optional[dict] = None, partition: str = 'aws') -> List[Edge]:
        """Fulfills expected method return_edges."""

        logger.info('Generating Edges based on ECS.')
        result = generate_edges_locally(nodes, scps, partition)

        for edge in result:
            logger.info("Found new edge: {}".format(edge.describe_edge()))

        return result

def process_batch(batch: List[Node], nodes: List[Node], progress_queue: Queue, service_linked_role_exists: bool, scps: Optional[List[List[dict]]] = None, partition: str = 'aws')-> List[Edge]:
    result = []
    for node_destination in batch:
        sim_result = resource_policy_authorization(
            'ecs-tasks.amazonaws.com',
            arns.get_account_id(node_destination.arn),
            node_destination.trust_policy,
            'sts:AssumeRole',
            node_destination.arn,
            {}
        )
        if sim_result is not ResourcePolicyEvalResult.SERVICE_MATCH:
            progress_queue.put(1)
            continue

        for node_source in nodes:
            if node_source == node_destination:
                continue

            if node_source.is_admin:
                continue

            # check that either the service-linked role exists or needs to be created
            create_slr_auth = False
            create_slr_mfa = False
            if not service_linked_role_exists:
                # using auth/mfa var, since the control flow continues to the next loop if we cannot make the SLR
                create_slr_auth, create_slr_mfa = query_interface.local_check_authorization_handling_mfa(
                    node_source,
                    'iam:CreateServiceLinkedRole',
                    f'arn:aws:iam::{arns.get_account_id(node_source.arn)}:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS',
                    {'iam:AWSServiceName': 'ecs.amazonaws.com'},
                    service_control_policy_groups=scps
                )
                if not create_slr_auth:
                    continue  # can't make the service-linked role -> can't use ECS (?)

            # check if someone can pass this role as an ECS Task Role
            pass_role_auth, pass_role_mfa = query_interface.local_check_authorization_handling_mfa(
                node_source,
                'iam:PassRole',
                node_destination.arn,
                {'iam:PassedToService': 'ecs-tasks.amazonaws.com'},  # verified via managed policies,
                service_control_policy_groups=scps
            )

            if not pass_role_auth:
                continue

            # check if someone can start/run a task
            run_task_auth, run_task_mfa = query_interface.local_check_authorization_handling_mfa(
                node_source,
                'ecs:RunTask',
                '*',
                {},
                service_control_policy_groups=scps
            )

            if not run_task_auth:
                continue

            reason = f'{"(requires MFA) " if create_slr_mfa or pass_role_mfa or run_task_mfa else ""}can ' \
                     f'{"use the existing ECS Service-Linked Role" if service_linked_role_exists else "create the ECS Service-Linked Role"} ' \
                     f'to run a task in ECS and access '

            result.append(Edge(
                node_source, node_destination, reason, 'ECS'
            ))

        progress_queue.put(1)

    return result    

def generate_edges_locally(nodes: List[Node], scps: Optional[List[List[dict]]] = None, partition: str = 'aws') -> List[Edge]:
    """Generates and returns Edge objects. It is possible to use this method if you are operating offline (infra-as-code).
    """
    # TODO: pull and include existing clusters, tasks, services
    
    service_linked_role_exists = False
    for node in nodes:
        if ':role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS' in node.arn:
            service_linked_role_exists = True  # can update to point to node if we need to do intermediate checks
            break


    edges = []
    role_nodes = [node for node in nodes if ':role/' in node.arn]
    total_nodes = len(role_nodes)

    num_processes = max(cpu_count() - 1, 1)  # Number of CPU cores minus one, but at least 1
    base_batch_size = len(role_nodes) // num_processes
    remainder = len(role_nodes) % num_processes
    batch_size = base_batch_size + (1 if remainder > 0 else 0)
    
    with Manager() as manager:
        # Create a Queue to track the progress
        progress_queue = manager.Queue()

        # Create batches of nodes
        batches = [role_nodes[i:i + batch_size] for i in range(0, len(role_nodes), batch_size)]

        with Pool(processes=num_processes) as pool:
            pool_result = pool.starmap_async(process_batch, [(batch, nodes, progress_queue, service_linked_role_exists, scps) for batch in batches])

            with Progress() as progress:
                task = progress.add_task("[green]Processing ECS edges...", total=total_nodes)

                while not pool_result.ready():
                    try:
                        # Collect in progress
                        while not progress_queue.empty():
                            # Advance the progress bar
                            progress.advance(task, progress_queue.get_nowait())
                        time.sleep(0.1)
                    except KeyboardInterrupt:
                        pool.terminate()
                        break
                
                # Final drain in case any items are left in the queue
                while not progress_queue.empty():
                    progress.advance(task, progress_queue.get_nowait())

        results = pool_result.get()
        for result in results:
            edges.extend(result)

    return edges
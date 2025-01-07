"""Code to coordinate identifying edges between principals in an AWS account"""

#  Copyright (c) NCC Group and Erik Steringer 2019. This file is part of Principal Mapper.
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

import logging
from typing import List, Optional

import botocore.session

from principalmapper.common import Edge, Node
from principalmapper.graphing.autoscaling_edges import AutoScalingEdgeChecker
from principalmapper.graphing.cloudformation_edges import CloudFormationEdgeChecker
from principalmapper.graphing.codebuild_edges import CodeBuildEdgeChecker
from principalmapper.graphing.ec2_edges import EC2EdgeChecker
from principalmapper.graphing.iam_edges import IAMEdgeChecker
from principalmapper.graphing.lambda_edges import LambdaEdgeChecker
from principalmapper.graphing.sagemaker_edges import SageMakerEdgeChecker
from principalmapper.graphing.ssm_edges import SSMEdgeChecker
from principalmapper.graphing.sts_edges import STSEdgeChecker

from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial

logger = logging.getLogger(__name__)


# Externally referable dictionary with all the supported edge-checking types
checker_map = {
    'autoscaling': AutoScalingEdgeChecker,
    'cloudformation': CloudFormationEdgeChecker,
    'codebuild': CodeBuildEdgeChecker,
    'ec2': EC2EdgeChecker,
    'iam': IAMEdgeChecker,
    'lambda': LambdaEdgeChecker,
    'sagemaker': SageMakerEdgeChecker,
    'ssm': SSMEdgeChecker,
    'sts': STSEdgeChecker
}


def check_service_edges(checker_name: str, session: botocore.session.Session,
                        nodes: List[Node], region_allow_list: Optional[List[str]],
                        region_deny_list: Optional[List[str]],
                        scps: Optional[List[List[dict]]],
                        client_args_map: Optional[dict]) -> List[Edge]:
    """Helper function to check edges for a single service"""
    if checker_name not in checker_map:
        return []

    checker_obj = checker_map[checker_name](session)
    return checker_obj.return_edges(nodes, region_allow_list, region_deny_list, scps, client_args_map)


def obtain_edges(session: Optional[botocore.session.Session],
                 checker_list: List[str],
                 nodes: List[Node],
                 region_allow_list: Optional[List[str]] = None,
                 region_deny_list: Optional[List[str]] = None,
                 scps: Optional[List[List[dict]]] = None,
                 client_args_map: Optional[dict] = None,
                 max_workers: int = None) -> List[Edge]:
    """
    Given a list of nodes and a botocore Session, return a list of edges between those nodes.
    Only checks against services passed in the checker_list param.

    Args:
        session: Botocore session
        checker_list: List of service checkers to run
        nodes: List of nodes to check connections between
        region_allow_list: Optional list of allowed regions
        region_deny_list: Optional list of denied regions
        scps: Optional list of service control policies
        client_args_map: Optional map of client arguments
        max_workers: Maximum number of thread workers (defaults to min(32, len(checker_list)))

    Returns:
        List[Edge]: List of edges found between nodes
    """
    if not checker_list:
        return []

    # Filter invalid checkers early
    valid_checkers = [check for check in checker_list if check in checker_map]
    if not valid_checkers:
        return []

    logger.info('Initiating edge checks.')
    logger.debug('Services being checked for edges: %s', valid_checkers)

    # Create partial function with fixed arguments
    check_func = partial(check_service_edges,
                         session=session,
                         nodes=nodes,
                         region_allow_list=region_allow_list,
                         region_deny_list=region_deny_list,
                         scps=scps,
                         client_args_map=client_args_map)

    # Default max_workers to min(32, len(valid_checkers))
    if max_workers is None:
        max_workers = min(32, len(valid_checkers))

    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_checker = {
            executor.submit(check_func, checker): checker
            for checker in valid_checkers
        }

        # Collect results as they complete
        for future in as_completed(future_to_checker):
            checker = future_to_checker[future]
            try:
                edges = future.result()
                results.extend(edges)
            except Exception as exc:
                logger.error('Checker %s generated an exception: %s', checker, exc)
                continue

    return results

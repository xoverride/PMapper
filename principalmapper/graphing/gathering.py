import concurrent.futures
import io
import json
import logging
import os
from typing import List, Optional, Dict, Any, Tuple

import botocore.session
import botocore.exceptions
import principalmapper
from principalmapper.common import Node, Group, Policy, Graph, OrganizationTree, OrganizationNode, OrganizationAccount
from principalmapper.graphing import edge_identification
from principalmapper.querying import query_interface
from principalmapper.util import arns
from principalmapper.util.botocore_tools import get_regions_to_search

logger = logging.getLogger(__name__)

class ConcurrentAWSMapper:
    def __init__(self, session: botocore.session.Session, max_workers: int = 10):
        self.session = session
        self.max_workers = max_workers
        self.sts_client = session.create_client('sts')
        self.caller_identity = self.sts_client.get_caller_identity()
        self.account_id = self.caller_identity['Account']
        
    def create_graph(self, service_list: list, 
                    region_allow_list: Optional[List[str]] = None,
                    region_deny_list: Optional[List[str]] = None, 
                    scps: Optional[List[List[dict]]] = None,
                    client_args_map: Optional[dict] = None) -> Graph:
        """Optimized version of create_graph using concurrent operations."""
        if client_args_map is None:
            client_args_map = {}

        metadata = {
            'account_id': self.account_id,
            'pmapper_version': principalmapper.__version__
        }

        # Get IAM client with provided arguments
        iamargs = client_args_map.get('iam', {})
        iamclient = self.session.create_client('iam', **iamargs)

        # Get nodes, groups, and policies concurrently
        results = self._get_nodes_groups_and_policies_concurrent(iamclient)
        nodes_result = results['nodes']
        groups_result = results['groups']
        policies_result = results['policies']

        # Update admin status
        self._update_admin_status_concurrent(nodes_result, scps)

        # Generate edges
        edges_result = edge_identification.obtain_edges(
            self.session,
            service_list,
            nodes_result,
            region_allow_list,
            region_deny_list,
            scps,
            client_args_map
        )

        # Gather resource policies concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._get_s3_bucket_policies, client_args_map): 'S3',
                executor.submit(self._get_sns_topic_policies, region_allow_list, region_deny_list, client_args_map): 'SNS',
                executor.submit(self._get_sqs_queue_policies, region_allow_list, region_deny_list, client_args_map): 'SQS',
                executor.submit(self._get_kms_key_policies, region_allow_list, region_deny_list, client_args_map): 'KMS',
                executor.submit(self._get_secrets_manager_policies, region_allow_list, region_deny_list, client_args_map): 'Secrets'
            }

            for future in concurrent.futures.as_completed(futures):
                service = futures[future]
                try:
                    service_policies = future.result()
                    policies_result.extend(service_policies)
                    logger.info(f"Successfully gathered policies from {service}")
                except Exception as e:
                    logger.warning(f"Failed to gather policies from {service}: {str(e)}")

        return Graph(nodes_result, edges_result, policies_result, groups_result, metadata)

    def _get_nodes_groups_and_policies_concurrent(self, iamclient) -> dict:
        """Concurrent version of get_nodes_groups_and_policies."""
        logger.info('Obtaining IAM Users/Roles/Groups/Policies in the account.')
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Start concurrent fetches for authorization details
            future_to_filter = {}
            for filter_type in ['User', 'Group', 'Role', 'LocalManagedPolicy', 'AWSManagedPolicy']:
                future = executor.submit(self._get_authorization_details, iamclient, filter_type)
                future_to_filter[future] = filter_type

            user_results = []
            group_results = []
            role_results = []
            policy_results = []

            for future in concurrent.futures.as_completed(future_to_filter):
                filter_type = future_to_filter[future]
                try:
                    results = future.result()
                    if filter_type == 'User':
                        user_results.extend(results)
                    elif filter_type == 'Group':
                        group_results.extend(results)
                    elif filter_type == 'Role':
                        role_results.extend(results)
                    elif filter_type in ['LocalManagedPolicy', 'AWSManagedPolicy']:
                        policy_results.extend(results)
                except Exception as e:
                    logger.error(f"Error getting {filter_type} details: {str(e)}")

        # Process the results concurrently
        result = {
            'nodes': [],
            'groups': [],
            'policies': []
        }

        # Process policies first as they're needed by users and groups
        for p in policy_results:
            doc = [x['Document'] for x in p['PolicyVersionList'] if x['IsDefaultVersion']][0]
            result['policies'].append(
                Policy(p['Arn'], p['PolicyName'], doc)
            )

        # Process groups
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            group_futures = [executor.submit(self._process_group, g, result['policies']) 
                           for g in group_results]
            
            for future in concurrent.futures.as_completed(group_futures):
                try:
                    group = future.result()
                    result['groups'].append(group)
                except Exception as e:
                    logger.error(f"Error processing group: {str(e)}")

        # Process users and roles concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            node_futures = []
            for u in user_results:
                node_futures.append(executor.submit(self._process_user, u, result['policies'], result['groups']))
            for r in role_results:
                node_futures.append(executor.submit(self._process_role, r, result['policies']))

            for future in concurrent.futures.as_completed(node_futures):
                try:
                    node = future.result()
                    result['nodes'].append(node)
                except Exception as e:
                    logger.error(f"Error processing node: {str(e)}")

        # Get MFA and access key information concurrently
        self._enrich_user_information_concurrent(iamclient, result['nodes'])

        return result

    def _get_authorization_details(self, iamclient, filter_type: str) -> List[Dict]:
        """Helper method to get authorization details for a specific filter."""
        results = []
        paginator = iamclient.get_paginator('get_account_authorization_details')
        for page in paginator.paginate(Filter=[filter_type]):
            if filter_type == 'User':
                results.extend(page['UserDetailList'])
            elif filter_type == 'Group':
                results.extend(page['GroupDetailList'])
            elif filter_type == 'Role':
                results.extend(page['RoleDetailList'])
            elif filter_type in ['LocalManagedPolicy', 'AWSManagedPolicy']:
                results.extend(page['Policies'])
        return results

    def _process_group(self, group: Dict, policies: List[Policy]) -> Group:
        """Process a single group's information."""
        group_policies = []
        
        # Process inline policies
        if 'GroupPolicyList' in group:
            for p in group['GroupPolicyList']:
                group_policies.append(
                    Policy(
                        group['Arn'],
                        p['PolicyName'],
                        p['PolicyDocument']
                    )
                )

        # Process attached policies
        for p in group['AttachedManagedPolicies']:
            group_policies.append(self._get_policy_by_arn_or_raise(p['PolicyArn'], policies))

        return Group(group['Arn'], group_policies)

    def _process_user(self, user: Dict, policies: List[Policy], groups: List[Group]) -> Node:
        """Process a single user's information."""
        user_policies = []
        
        # Process inline policies
        if 'UserPolicyList' in user:
            for p in user['UserPolicyList']:
                user_policies.append(
                    Policy(
                        user['Arn'],
                        p['PolicyName'],
                        p['PolicyDocument']
                    )
                )

        # Process attached policies
        for p in user['AttachedManagedPolicies']:
            user_policies.append(self._get_policy_by_arn_or_raise(p['PolicyArn'], policies))

        # Get permissions boundary
        boundary_policy = None
        if 'PermissionsBoundary' in user:
            boundary_policy = self._get_policy_by_arn_or_raise(
                user['PermissionsBoundary']['PermissionsBoundaryArn'],
                policies
            )

        # Get group memberships
        group_list = []
        for group_name in user['GroupList']:
            for group in groups:
                if arns.get_resource(group.arn).split('/')[-1] == group_name:
                    group_list.append(group)
                    break

        # Process tags
        tags = {}
        if 'Tags' in user:
            tags = {tag['Key']: tag['Value'] for tag in user['Tags']}

        return Node(
            user['Arn'],
            user['UserId'],
            user_policies,
            group_list,
            None,
            None,
            0,  # access_keys will be updated later
            'PasswordLastUsed' in user,
            False,  # is_admin will be updated later
            boundary_policy,
            False,  # has_mfa will be updated later
            tags
        )

    def _process_role(self, role: Dict, policies: List[Policy]) -> Node:
        """Process a single role's information."""
        role_policies = []
        
        # Process inline policies
        for p in role['RolePolicyList']:
            role_policies.append(
                Policy(
                    role['Arn'],
                    p['PolicyName'],
                    p['PolicyDocument']
                )
            )

        # Process attached policies
        for p in role['AttachedManagedPolicies']:
            role_policies.append(self._get_policy_by_arn_or_raise(p['PolicyArn'], policies))

        # Process tags
        tags = {}
        if 'Tags' in role:
            tags = {tag['Key']: tag['Value'] for tag in role['Tags']}

        return Node(
            role['Arn'],
            role['RoleId'],
            role_policies,
            None,
            role['AssumeRolePolicyDocument'],
            [x['Arn'] for x in role['InstanceProfileList']],
            0,
            False,
            False,
            None,
            False,
            tags
        )

    def _enrich_user_information_concurrent(self, iamclient, nodes: List[Node]):
        """Concurrently gather and update user information (access keys, MFA devices)."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for node in nodes:
                if arns.get_resource(node.arn).startswith('user/'):
                    username = arns.get_resource(node.arn).split('/')[-1]
                    futures.append(executor.submit(
                        self._get_user_details,
                        iamclient,
                        username,
                        node
                    ))

            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error enriching user information: {str(e)}")

    def _get_user_details(self, iamclient, username: str, node: Node):
        """Get detailed information for a single user."""
        # Get access keys
        try:
            access_keys = iamclient.list_access_keys(UserName=username)
            node.access_keys = len(access_keys['AccessKeyMetadata'])
        except Exception as e:
            logger.warning(f"Failed to get access keys for user {username}: {str(e)}")

        # Get login profile
        try:
            login_profile = iamclient.get_login_profile(UserName=username)
            node.active_password = 'LoginProfile' in login_profile
        except botocore.exceptions.ClientError as e:
            if 'NoSuchEntity' in str(e):
                node.active_password = False
            else:
                raise e

        # Get MFA devices
        try:
            mfa_devices = iamclient.list_mfa_devices(UserName=username)
            node.has_mfa = len(mfa_devices['MFADevices']) > 0
        except Exception as e:
            logger.warning(f"Failed to get MFA devices for user {username}: {str(e)}")

    def _update_admin_status_concurrent(self, nodes: List[Node], scps: Optional[List[List[dict]]] = None):
        """Concurrently update admin status for nodes."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self._check_admin_status, node, scps) for node in nodes]
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error updating admin status: {str(e)}")

    def _check_admin_status(self, node: Node, scps: Optional[List[List[dict]]]):
        """Check admin status for a single node."""
        node_type = arns.get_resource(node.arn).split('/')[0]
        
        # Check self-policy modification
        action = 'iam:PutUserPolicy' if node_type == 'user' else 'iam:PutRolePolicy'
        if query_interface.local_check_authorization_handling_mfa(node, action, node.arn, {}, service_control_policy_groups=scps)[0]:
            node.is_admin = True
            return

        # Check AdministratorAccess policy attachment
        action = 'iam:AttachUserPolicy' if node_type == 'user' else 'iam:AttachRolePolicy'
        condition_keys = {'iam:PolicyARN': 'arn:aws:iam::aws:policy/AdministratorAccess'}
        if query_interface.local_check_authorization_handling_mfa(node, action, node.arn, condition_keys, service_control_policy_groups=scps)[0]:
            node.is_admin = True
            return

        # Additional admin checks as in original code...
        # (Rest of the
        # Check if node can create a role and attach admin policies
        if query_interface.local_check_authorization_handling_mfa(node, 'iam:CreateRole', '*', {}, service_control_policy_groups=scps)[0]:
            if query_interface.local_check_authorization_handling_mfa(node, 'iam:AttachRolePolicy', '*',
                                                                    {'iam:PolicyARN': 'arn:aws:iam::aws:policy/AdministratorAccess'},
                                                                    service_control_policy_groups=scps)[0]:
                node.is_admin = True
                return
            if query_interface.local_check_authorization_handling_mfa(node, 'iam:PutRolePolicy', '*', {},
                                                                    service_control_policy_groups=scps)[0]:
                node.is_admin = True
                return

        # Check customer managed policy update permissions
        for attached_policy in node.attached_policies:
            if attached_policy.arn != node.arn and ':aws:policy/' not in attached_policy.arn:
                if query_interface.local_check_authorization_handling_mfa(node, 'iam:CreatePolicyVersion',
                                                                        attached_policy.arn, {},
                                                                        service_control_policy_groups=scps)[0]:
                    node.is_admin = True
                    return

        # Check group policy permissions for users
        if node_type == 'user':
            for group in node.group_memberships:
                if query_interface.local_check_authorization_handling_mfa(node, 'iam:PutGroupPolicy', group.arn, {},
                                                                        service_control_policy_groups=scps)[0]:
                    node.is_admin = True
                    return

                condition_keys = {'iam:PolicyARN': 'arn:aws:iam::aws:policy/AdministratorAccess'}
                if query_interface.local_check_authorization_handling_mfa(node, 'iam:AttachGroupPolicy', group.arn,
                                                                        condition_keys,
                                                                        service_control_policy_groups=scps)[0]:
                    node.is_admin = True
                    return

                for attached_policy in group.attached_policies:
                    if attached_policy.arn != group.arn and ':aws:policy/' not in attached_policy.arn:
                        if query_interface.local_check_authorization_handling_mfa(node, 'iam:CreatePolicyVersion',
                                                                                attached_policy.arn, {},
                                                                                service_control_policy_groups=scps)[0]:
                            node.is_admin = True
                            return

    def _get_s3_bucket_policies(self, client_args_map: Optional[dict] = None) -> List[Policy]:
        """Concurrently gather S3 bucket policies."""
        s3args = client_args_map.get('s3', {}) if client_args_map else {}
        s3client = self.session.create_client('s3', **s3args)

        try:
            buckets = s3client.list_buckets()['Buckets']
        except Exception as e:
            logger.error(f"Failed to list S3 buckets: {str(e)}")
            return []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._get_single_bucket_policy, s3client, bucket['Name']): bucket['Name']
                for bucket in buckets
            }

            policies = []
            for future in concurrent.futures.as_completed(futures):
                bucket_name = futures[future]
                try:
                    policy = future.result()
                    if policy:
                        policies.append(policy)
                except Exception as e:
                    logger.warning(f"Failed to get policy for bucket {bucket_name}: {str(e)}")

        return policies

    def _get_single_bucket_policy(self, s3client, bucket_name: str) -> Optional[Policy]:
        """Get policy for a single S3 bucket."""
        bucket_arn = f'arn:aws:s3:::{bucket_name}'
        try:
            policy = json.loads(s3client.get_bucket_policy(Bucket=bucket_name)['Policy'])
            logger.info(f'Caching policy for {bucket_arn}')
            return Policy(bucket_arn, bucket_name, policy)
        except botocore.exceptions.ClientError as e:
            if 'NoSuchBucketPolicy' in str(e):
                logger.info(f'Bucket {bucket_name} does not have a bucket policy, adding a "stub" policy instead.')
                return Policy(
                    bucket_arn,
                    bucket_name,
                    {
                        "Statement": [],
                        "Version": "2012-10-17"
                    }
                )
            else:
                logger.warning(f'Unable to retrieve bucket policy for {bucket_name}. Error: {str(e)}')
                return None

    def _get_kms_key_policies(self, region_allow_list: Optional[List[str]] = None,
                            region_deny_list: Optional[List[str]] = None,
                            client_args_map: Optional[dict] = None) -> List[Policy]:
        """Concurrently gather KMS key policies across regions."""
        kmsargs = client_args_map.get('kms', {}) if client_args_map else {}
        regions = get_regions_to_search(self.session, 'kms', region_allow_list, region_deny_list)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._get_kms_policies_for_region, region, kmsargs): region
                for region in regions
            }

            policies = []
            for future in concurrent.futures.as_completed(futures):
                region = futures[future]
                try:
                    region_policies = future.result()
                    policies.extend(region_policies)
                except Exception as e:
                    logger.warning(f"Failed to get KMS policies in region {region}: {str(e)}")

        return policies

    def _get_kms_policies_for_region(self, region: str, kmsargs: dict) -> List[Policy]:
        """Get KMS policies for a single region."""
        kmsclient = self.session.create_client('kms', region_name=region, **kmsargs)
        keys = []

        try:
            paginator = kmsclient.get_paginator('list_keys')
            for page in paginator.paginate():
                keys.extend(page['Keys'])
        except Exception as e:
            logger.warning(f"Failed to list KMS keys in region {region}: {str(e)}")
            return []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._get_single_kms_policy, kmsclient, key['KeyId']): key['KeyId']
                for key in keys
            }

            policies = []
            for future in concurrent.futures.as_completed(futures):
                key_id = futures[future]
                try:
                    policy = future.result()
                    if policy:
                        policies.append(policy)
                except Exception as e:
                    logger.warning(f"Failed to get policy for KMS key {key_id}: {str(e)}")

        return policies

    def _get_single_kms_policy(self, kmsclient, key_id: str) -> Optional[Policy]:
        """Get policy for a single KMS key."""
        try:
            policy_str = kmsclient.get_key_policy(KeyId=key_id, PolicyName='default')['Policy']
            policy = json.loads(policy_str)
            return Policy(key_id, key_id.split('/')[-1], policy)
        except Exception as e:
            logger.warning(f"Failed to get policy for KMS key {key_id}: {str(e)}")
            return None

    def _get_sns_topic_policies(self, region_allow_list: Optional[List[str]] = None,
                             region_deny_list: Optional[List[str]] = None,
                             client_args_map: Optional[dict] = None) -> List[Policy]:
        """Concurrently gather SNS topic policies across regions."""
        snsargs = client_args_map.get('sns', {}) if client_args_map else {}
        regions = get_regions_to_search(self.session, 'sns', region_allow_list, region_deny_list)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._get_sns_policies_for_region, region, snsargs): region
                for region in regions
            }

            policies = []
            for future in concurrent.futures.as_completed(futures):
                region = futures[future]
                try:
                    region_policies = future.result()
                    policies.extend(region_policies)
                except Exception as e:
                    logger.warning(f"Failed to get SNS policies in region {region}: {str(e)}")

        return policies

    def _get_sns_policies_for_region(self, region: str, snsargs: dict) -> List[Policy]:
        """Get SNS policies for a single region."""
        snsclient = self.session.create_client('sns', region_name=region, **snsargs)
        topics = []

        try:
            paginator = snsclient.get_paginator('list_topics')
            for page in paginator.paginate():
                topics.extend(page['Topics'])
        except Exception as e:
            logger.warning(f"Failed to list SNS topics in region {region}: {str(e)}")
            return []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._get_single_sns_policy, snsclient, topic['TopicArn']): topic['TopicArn']
                for topic in topics
            }

            policies = []
            for future in concurrent.futures.as_completed(futures):
                topic_arn = futures[future]
                try:
                    policy = future.result()
                    if policy:
                        policies.append(policy)
                except Exception as e:
                    logger.warning(f"Failed to get policy for SNS topic {topic_arn}: {str(e)}")

        return policies

    def _get_single_sns_policy(self, snsclient, topic_arn: str) -> Optional[Policy]:
        """Get policy for a single SNS topic."""
        try:
            attributes = snsclient.get_topic_attributes(TopicArn=topic_arn)['Attributes']
            if 'Policy' in attributes:
                policy = json.loads(attributes['Policy'])
                return Policy(topic_arn, topic_arn.split(':')[-1], policy)
        except Exception as e:
            logger.warning(f"Failed to get policy for SNS topic {topic_arn}: {str(e)}")
            return None

    def _get_sqs_queue_policies(self, region_allow_list: Optional[List[str]] = None,
                             region_deny_list: Optional[List[str]] = None,
                             client_args_map: Optional[dict] = None) -> List[Policy]:
        """Concurrently gather SQS queue policies across regions."""
        sqsargs = client_args_map.get('sqs', {}) if client_args_map else {}
        regions = get_regions_to_search(self.session, 'sqs', region_allow_list, region_deny_list)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._get_single_sqs_policy, region, sqsargs): region
                for region in regions
            }

            policies = []
            for future in concurrent.futures.as_completed(futures):
                region = futures[future]
                try:
                    region_policies = future.result()
                    policies.extend(region_policies)
                except Exception as e:
                    logger.warning(f"Failed to get SQS policies in region {region}: {str(e)}")

        return policies

    def _get_single_sqs_policy(self, sqsclient, queue_url: str, region: str) -> Optional[Policy]:
        """Get policy for a single SQS queue."""
        try:
            queue_name = queue_url.split('/')[-1]
            attributes = sqsclient.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['Policy'])

            if 'Policy' in attributes['Attributes']:
                policy = json.loads(attributes['Attributes']['Policy'])
            else:
                policy = {"Statement": [], "Version": "2012-10-17"}

            queue_arn = f'arn:aws:sqs:{region}:{self.account_id}:{queue_name}'
            return Policy(queue_arn, queue_name, policy)
        except Exception as e:
            logger.warning(f"Failed to get policy for SQS queue {queue_url}: {str(e)}")
            return None

    def _get_secrets_manager_policies(self, region_allow_list: Optional[List[str]] = None,
                                   region_deny_list: Optional[List[str]] = None,
                                   client_args_map: Optional[dict] = None) -> List[Policy]:
        """Concurrently gather Secrets Manager policies across regions."""
        smargs = client_args_map.get('secretsmanager', {}) if client_args_map else {}
        regions = get_regions_to_search(self.session, 'secretsmanager', region_allow_list, region_deny_list)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._get_secrets_policies_for_region, region, smargs): region
                for region in regions
            }

            policies = []
            for future in concurrent.futures.as_completed(futures):
                region = futures[future]
                try:
                    region_policies = future.result()
                    policies.extend(region_policies)
                except Exception as e:
                    logger.warning(f"Failed to get Secrets Manager policies in region {region}: {str(e)}")

        return policies

    def _get_secrets_policies_for_region(self, region: str, smargs: dict) -> List[Policy]:
        """Get Secrets Manager policies for a single region."""
        smclient = self.session.create_client('secretsmanager', region_name=region, **smargs)
        secrets = []

        try:
            paginator = smclient.get_paginator('list_secrets')
            for page in paginator.paginate():
                if 'SecretList' in page:
                    for secret in page['SecretList']:
                        if 'PrimaryRegion' not in secret or secret['PrimaryRegion'] == region:
                            secrets.append(secret)
        except Exception as e:
            logger.warning(f"Failed to list secrets in region {region}: {str(e)}")
            return []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._get_single_secret_policy, smclient, secret['ARN'], secret['Name']): secret['ARN']
                for secret in secrets
            }

            policies = []
            for future in concurrent.futures.as_completed(futures):
                secret_arn = futures[future]
                try:
                    policy = future.result()
                    if policy:
                        policies.append(policy)
                except Exception as e:
                    logger.warning(f"Failed to get policy for secret {secret_arn}: {str(e)}")

        return policies

    def _get_single_secret_policy(self, smclient, secret_arn: str, secret_name: str) -> Optional[Policy]:
        """Get policy for a single Secrets Manager secret."""
        try:
            response = smclient.get_resource_policy(SecretId=secret_arn)
            
            if 'ResourcePolicy' in response and response['ResourcePolicy']:
                policy = json.loads(response['ResourcePolicy'])
            else:
                policy = {"Statement": [], "Version": "2012-10-17"}
                
            return Policy(secret_arn, secret_name, policy)
        except Exception as e:
            logger.warning(f"Failed to get policy for secret {secret_arn}: {str(e)}")
            return None

    @staticmethod
    def _get_policy_by_arn(arn: str, policies: List[Policy]) -> Optional[Policy]:
        """Helper function to find a policy by ARN."""
        return next((policy for policy in policies if policy.arn == arn), None)

    @staticmethod
    def _get_policy_by_arn_or_raise(arn: str, policies: List[Policy]) -> Policy:
        """Helper function to find a policy by ARN or raise an exception."""
        policy = ConcurrentAWSMapper._get_policy_by_arn(arn, policies)
        if policy is None:
            raise ValueError(f'Could not locate policy {arn}.')
        return policy

    def get_organizations_data(self) -> OrganizationTree:
        """Optimized version of get_organizations_data using concurrent operations."""
        try:
            orgsclient = self.session.create_client('organizations')
            organization_data = orgsclient.describe_organization()
        except botocore.exceptions.ClientError as ex:
            if 'AccessDeniedException' in str(ex):
                raise RuntimeError(
                    f'Encountered a permission error. Either the current principal ({self.caller_identity["Arn"]}) '
                    f'is not authorized to interact with AWS Organizations, or the current account '
                    f'({self.account_id}) is not the management account'
                )
            raise ex

        org_tree = OrganizationTree(
            organization_data['Organization']['Id'],
            organization_data['Organization']['MasterAccountId'],
            None,  # root_ous will be set later
            None,  # SCPs will be set later
            None,  # account list will be set later
            [],    # edge list to be set by caller
            {'pmapper_version': principalmapper.__version__}
        )

        # Get root IDs concurrently
        root_ids_and_names = self._get_organization_roots(orgsclient)
        
        # Process roots concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            root_futures = {
                executor.submit(self._process_organizational_unit, orgsclient, root_id, root_name): root_id
                for root_id, root_name in root_ids_and_names
            }

            root_ous = []
            scps = []
            account_ids = set()

            for future in concurrent.futures.as_completed(root_futures):
                root_id = root_futures[future]
                try:
                    ou_data, ou_scps, ou_accounts = future.result()
                    root_ous.append(ou_data)
                    scps.extend(ou_scps)
                    account_ids.update(ou_accounts)
                except Exception as e:
                    logger.error(f"Failed to process root OU {root_id}: {str(e)}")

        # Remove duplicate SCPs and set results
        org_tree.root_ous = root_ous
        org_tree.all_scps = list({scp.arn: scp for scp in scps}.values())
        org_tree.accounts = list(account_ids)

        return org_tree

    def _get_organization_roots(self, orgsclient) -> List[Tuple[str, str]]:
        """Get organization root IDs and names."""
        root_ids_and_names = []
        paginator = orgsclient.get_paginator('list_roots')
        for page in paginator.paginate():
            root_ids_and_names.extend([(x['Id'], x['Name']) for x in page['Roots']])
        return root_ids_and_names

    def _process_organizational_unit(self, orgsclient, ou_id: str, ou_name: str) -> Tuple[OrganizationNode, List[Policy], set]:
        """Process a single organizational unit and its children concurrently."""
        logger.info(f'Processing organizational unit "{ou_name}" ({ou_id})')

        # Get OU data concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            tags_future = executor.submit(self._get_tags_for_target, orgsclient, ou_id)
            scps_future = executor.submit(self._get_scps_for_target, orgsclient, ou_id)
            accounts_future = executor.submit(self._get_accounts_for_parent, orgsclient, ou_id)

            try:
                ou_tags = tags_future.result()
                ou_scps = scps_future.result()
                ou_accounts, account_scps = accounts_future.result()
            except Exception as e:
                logger.error(f"Failed to get OU data for {ou_id}: {str(e)}")
                raise

        # Process child OUs concurrently
        child_ou_ids = self._get_child_ous(orgsclient, ou_id)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            child_futures = {}
            for child_id in child_ou_ids:
                try:
                    child_data = orgsclient.describe_organizational_unit(OrganizationalUnitId=child_id)
                    child_futures[executor.submit(
                        self._process_organizational_unit,
                        orgsclient,
                        child_id,
                        child_data['OrganizationalUnit']['Name']
                    )] = child_id
                except Exception as e:
                    logger.error(f"Failed to process child OU {child_id}: {str(e)}")
                    continue

            child_ous = []
            child_scps = []
            child_account_ids = set()

            for future in concurrent.futures.as_completed(child_futures):
                child_id = child_futures[future]
                try:
                    child_ou, child_ou_scps, child_ou_accounts = future.result()
                    child_ous.append(child_ou)
                    child_scps.extend(child_ou_scps)
                    child_account_ids.update(child_ou_accounts)
                except Exception as e:
                    logger.error(f"Failed to process child OU data {child_id}: {str(e)}")

        # Combine all SCPs and account IDs
        all_scps = ou_scps + account_scps + child_scps
        all_account_ids = set(ou_accounts.keys()) | child_account_ids

        # Create the OrganizationNode
        org_node = OrganizationNode(
            ou_id,
            ou_name,
            [OrganizationAccount(acc_id, scps, ou_accounts[acc_id])
             for acc_id, scps in ou_accounts.items()],
            child_ous,
            ou_scps,
            ou_tags
        )

        return org_node, all_scps, all_account_ids

    def _get_tags_for_target(self, orgsclient, target_id: str) -> dict:
        """Get tags for an organizational target."""
        tags = {}
        try:
            paginator = orgsclient.get_paginator('list_tags_for_resource')
            for page in paginator.paginate(ResourceId=target_id):
                for tag in page['Tags']:
                    tags[tag['Key']] = tag['Value']
        except Exception as e:
            logger.warning(f"Failed to get tags for target {target_id}: {str(e)}")
        return tags

    def _get_scps_for_target(self, orgsclient, target_id: str) -> List[Policy]:
        """Get service control policies for a target."""
        policies = []
        try:
            paginator = orgsclient.get_paginator('list_policies_for_target')
            for page in paginator.paginate(TargetId=target_id, Filter='SERVICE_CONTROL_POLICY'):
                for policy in page['Policies']:
                    policy_data = orgsclient.describe_policy(PolicyId=policy['Arn'].split('/')[-1])
                    policies.append(Policy(
                        policy['Arn'],
                        policy['Name'],
                        json.loads(policy_data['Policy']['Content'])
                    ))
        except Exception as e:
            logger.warning(f"Failed to get SCPs for target {target_id}: {str(e)}")
        return policies

    def _get_accounts_for_parent(self, orgsclient, parent_id: str) -> Tuple[Dict[str, dict], List[Policy]]:
        """Get accounts and their tags for a parent OU."""
        accounts = {}
        all_scps = []
        
        try:
            paginator = orgsclient.get_paginator('list_accounts_for_parent')
            for page in paginator.paginate(ParentId=parent_id):
                for account in page['Accounts']:
                    account_id = account['Id']
                    
                    # Get account tags and SCPs concurrently
                    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                        tags_future = executor.submit(self._get_tags_for_target, orgsclient, account_id)
                        scps_future = executor.submit(self._get_scps_for_target, orgsclient, account_id)
                        
                        try:
                            account_tags = tags_future.result()
                            account_scps = scps_future.result()
                            
                            accounts[account_id] = account_tags
                            all_scps.extend(account_scps)
                        except Exception as e:
                            logger.warning(f"Failed to get data for account {account_id}: {str(e)}")
                            
        except Exception as e:
            logger.warning(f"Failed to get accounts for parent {parent_id}: {str(e)}")
            
        return accounts, all_scps

    def _get_child_ous(self, orgsclient, parent_id: str) -> List[str]:
        """Get child OUs for a parent OU."""
        child_ids = []
        try:
            paginator = orgsclient.get_paginator('list_children')
            for page in paginator.paginate(ParentId=parent_id, ChildType='ORGANIZATIONAL_UNIT'):
                child_ids.extend(child['Id'] for child in page['Children'])
        except Exception as e:
            logger.warning(f"Failed to get child OUs for parent {parent_id}: {str(e)}")
        return child_ids


def create_graph(session: botocore.session.Session, service_list: list,
                region_allow_list: Optional[List[str]] = None,
                region_deny_list: Optional[List[str]] = None,
                scps: Optional[List[List[dict]]] = None,
                client_args_map: Optional[dict] = None) -> Graph:
    """Optimized wrapper function to create a graph using the concurrent mapper."""
    mapper = ConcurrentAWSMapper(session)
    return mapper.create_graph(service_list, region_allow_list, region_deny_list, scps, client_args_map)


def create_graph_without_edges(*args, **kwargs) -> Graph:
    """Create a graph without computing edges, using the concurrent mapper."""
    graph = create_graph(*args, **kwargs)
    graph.edges = []
    return graph


def get_organizations_data(session: botocore.session.Session) -> OrganizationTree:
    """Optimized wrapper function to get organizations data using the concurrent mapper."""
    mapper = ConcurrentAWSMapper(session)
    return mapper.get_organizations_data()
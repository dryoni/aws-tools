#!/usr/bin/env python3
import boto3
import botocore
import click
from concurrent.futures import as_completed
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
import dns.resolver
import json
from netaddr import IPNetwork, IPAddress
import pickle
import re
import sys
import time

# ******************************************************************************************************************
# Change Log:
# Date           Who                Company           Change(s):
# ------------------------------------------------------------------------------------------------------------------
# 06/29/2022     Richard Knechtel   Blast Motion      Showing Network Interfaces and Security Group is attached to, 
#                                                     Showing all lambdas an SG is attached to, 
#                                                     Added usage for a python virtual environment
# ------------------------------------------------------------------------------------------------------------------
#
# ******************************************************************************************************************

# Console Text Colors:
BLUE = '\033[94m'
RED = '\033[91m'
GREEN = '\033[92m'
ENDC = '\033[0m'
YELLOW = '\033[93m'

def print_green(message, nl=True):
    click.echo(click.style(str(message), fg='bright_green'), nl=nl)


def print_blue(message, nl=True):
    click.echo(click.style(str(message), fg='bright_blue'), nl=nl)


def print_yellow(message, nl=True):
    click.echo(click.style(str(message), fg='bright_yellow'), nl=nl)


def print_red(message, nl=True):
    click.echo(click.style(str(message), fg='bright_red'), nl=nl)


def turn_red(string):
    return RED + string + ENDC


def turn_yellow(string):
    return YELLOW + string + ENDC


def turn_blue(string):
    return BLUE + string + ENDC


def turn_green(string):
    return GREEN + string + ENDC


def save_data(file_name, data):
    with open(file_name, 'wb') as f:
        pickle.dump(data, f)


def load_data(file_name):
    with open(file_name, 'rb') as f:
        return pickle.load(f)


class Boto:
    boto_clients = {}
    aws_cache = {}

    def __init__(self):
        return

    def get_client(self, service_name):
        try:
            client_service = self.boto_clients.get(service_name)
        except Exception as err:
            print_red(f'Error with service {service_name} - {str(err)}')
            raise(err)
        if not client_service:
            finished = False
            throttle_count = 0
            while not finished:
                try:
                    client_service = boto3.client(service_name)
                    finished = True
                except KeyError:
                    throttle_count += 1
                    throttle_wait_ms = 2**throttle_count/10
                    time.sleep(throttle_wait_ms)
                    continue
            self.boto_clients[service_name] = client_service
        return client_service

    def aws(self, service_name, function_name, max_results=0, quiet=False, cache=True, **kwargs):
        
        full_req_name = f'{service_name}:{function_name}:{kwargs}'
        if cache and full_req_name in self.aws_cache:
            return self.aws_cache[full_req_name]
        
        aws_functions_dict = {
            'ec2:describe_network_interfaces': {'token_name': 'NextToken', 'max_name': 'MaxResults', 'max_items': 1000, 'no_max_args': ['NetworkInterfaceIds']},
            'elasticache:describe_cache_clusters': {'token_name': 'Marker', 'max_name': 'MaxRecords', 'max_items': 100},
            'redshift:describe_clusters': {'token_name': 'Marker', 'max_name': 'MaxRecords', 'max_items': 100},
            'rds:describe_db_clusters': {'token_name': 'Marker', 'max_name': 'MaxRecords', 'max_items': 100},
            'rds:describe_db_instances': {'token_name': 'Marker', 'max_name': 'MaxRecords', 'max_items': 100},
            'efs:describe_file_systems': {'token_name': 'Marker', 'max_name': 'MaxItems', 'max_items': 1000},
            'ec2:describe_instances': {'token_name': 'NextToken', 'max_name': 'MaxResults', 'max_items': 10000, 'no_max_args': ['InstanceIds']},
            'dms:describe_replication_instances': {'token_name': 'Marker', 'max_name': 'MaxRecords', 'max_items': 100},
            'ec2:describe_subnets': {'token_name': 'NextToken', 'max_name': 'MaxResults', 'max_items': 1000, 'no_max_args': ['SubnetIds']},
            'ec2:describe_vpc_endpoints': {'token_name': 'NextToken', 'max_name': 'MaxResults', 'max_items': 10000},
            'ec2:describe_vpcs': {'token_name': 'NextToken', 'max_name': 'MaxResults', 'max_items': 1000, 'no_max_args': ['VpcIds']},
            'ecs:list_clusters': {'token_name': 'nextToken', 'max_name': 'maxResults', 'max_items': 100},
            'ecs:list_tasks': {'token_name': 'nextToken', 'max_name': 'maxResults', 'max_items': 100},
            'sagemaker:list_endpoints': {'token_name': 'NextToken', 'max_name': 'MaxResults', 'max_items': 100},
            'cloudtrail:lookup_events': {'token_name': 'NextToken', 'max_name': 'MaxResults', 'max_items': 50},
            'lambda:list_functions': {'token_name': 'Marker', 'max_name': 'MaxItems', 'max_items': 100},

        }
        
        next_token_key_names = ['NextMarker', 'NextToken', 'Marker', 'nextToken']

        object_list = []
        token_name = ''

        func_full_name = f'{service_name}:{function_name}'

        if func_full_name in aws_functions_dict:
            func_dict = aws_functions_dict[func_full_name]
            token_name = func_dict.get('token_name')
            max_name = func_dict.get('max_name')
            max_items = func_dict.get('max_items')
            no_max_args = func_dict['no_max_args'] if 'no_max_args' in func_dict else [
            ]
            if max_name and not (set(list(kwargs.keys())) & set(no_max_args)):
                kwargs[max_name] = max_items

        client = self.get_client(service_name)
        token = ''
        finished = False
        throttle_count = 0
        while not finished:
            if token and token_name:
                kwargs[token_name] = token
            try:
                response = getattr(client, function_name)(**kwargs)
                throttle_count = 0
            except botocore.exceptions.EndpointConnectionError:
                throttle_count += 1
                throttle_wait_ms = 2**throttle_count/10
                time.sleep(throttle_wait_ms)
                continue
            except client.exceptions.ClientError as err:
                if err.response['Error']['Code'] == 'Throttling':
                    throttle_count += 1
                    throttle_wait_ms = 2**throttle_count/10
                    time.sleep(throttle_wait_ms)
                    continue
                else:
                    err_msg = err.response['Error']['Message']
                    if not quiet:
                        print_red(f'Error running {full_req_name} - {err_msg}')
                    return []

            # get first element in response dict
            first_elem = response[list(response.keys())[0]]
            if not isinstance(first_elem, list):
                self.aws_cache[full_req_name] = response
                return response

            object_list += response[list(response.keys())[0]]

            found_token = False
            if token_name:
                for key in next_token_key_names:
                    if key in response:
                        token = response[key]
                        found_token = True
                        break

            if not found_token:
                finished = True

        self.aws_cache[full_req_name] = object_list
        return object_list


def get_rules(raw_list, sgs_names):
    rules = []
    for rule in raw_list:
        ip_protocol = rule.get('IpProtocol')
        from_port = rule.get('FromPort')
        to_port = rule.get('ToPort')
        cidr_info = rule.get('IpRanges')
        group_info = rule.get('UserIdGroupPairs')

        if ip_protocol:
            ip_protocol = ip_protocol.upper()

        if ip_protocol == "-1":
            ip_protocol = "ANY"
            ports = "ANY"
        elif ip_protocol == "47":
            ip_protocol = "GRE"
            ports = "GRE"
        elif not from_port or not to_port or from_port == -1 or to_port == -1:
            ports = ip_protocol
        elif from_port == to_port:
            ports = "%s %s" % (ip_protocol, from_port)
        else:
            ports = "%s %s-%s" % (ip_protocol, from_port, to_port)

        if cidr_info:
            for cidr_one_info in cidr_info:
                cidr = cidr_one_info.get('CidrIp')
                description = cidr_one_info.get('Description')
                if cidr:
                    cidr = re.sub(r'^(.+)/32$', r'\1', cidr)
                    cidr = re.sub(r'^0\.0\.0\.0/0$', 'ANY', cidr)

                if not description:
                    description = ''

                rules.append([ports, cidr, description])

        if group_info:
            for group_one_info in group_info:
                group_id = group_one_info.get('GroupId')
                description = group_one_info.get('Description')
                group_name = group_one_info.get('GroupName')
                if not group_name:
                    group_name = sgs_names.get(group_id)
                if group_name:
                    group = f'{group_id} ({group_name})'
                else:
                    group = group_id

                if not description:
                    description = ''
                rules.append([ports, group, description])
    return rules


def print_rules(rules_dict, direction=''):
    if not rules_dict:
        return
    max_ports = max([len(x[0]) for x in rules_dict])
    max_res = max([len(x[1]) for x in rules_dict])
    for rule in rules_dict:
        temp_max_ports = max_ports
        temp_max_res = max_res

        ports, resource, description = rule
        if not description:
            description = '{No Description}'
        if ports == 'ANY':
            ports = turn_red(ports)
            temp_max_ports += 9
        if resource == 'ANY' or re.match(r'^[0-9\.]+\/[0-7]$', resource):
            resource = turn_red(resource)
            temp_max_res += 9
        elif re.match(r'^sg\-.*$',resource) and not '(' in resource:
            resource = turn_red(f'{resource} (NOT Found)')
            temp_max_res += 9
        if direction:
            print('\t\t%s  %-*s  | %s' %
                  (turn_yellow(direction), temp_max_ports, ports, description))
        else:
            print('\t%-*s  %-*s  | %s' %
                  (temp_max_ports, ports, temp_max_res, resource, description))


def get_referenced_sgs(full_sg_name, all_sgs, sgs_names):
    referenced = {}
    for temp_sg in all_sgs:
        temp_sg_id = temp_sg['GroupId']
        temp_sg_name = temp_sg['GroupName']
        temp_full_sg_name = f'{temp_sg_id} ({temp_sg_name})'
        inbound_rules_raw = temp_sg['IpPermissions']
        outbound_rules_raw = temp_sg['IpPermissionsEgress']
        rules = get_rules(inbound_rules_raw, sgs_names) + \
            get_rules(outbound_rules_raw, sgs_names)
        found = False
        for rule in rules:
            if rule[1] == full_sg_name:
                found = True
                break
        if found:
            referenced[temp_full_sg_name] = temp_sg_id
    return referenced


def get_elasticache_instances():
    es_instances = Boto().aws('elasticache', 'describe_cache_clusters', ShowCacheNodeInfo=True)
    result = {}
    for instance in es_instances:
        name = instance['CacheClusterId']
        engine = instance['Engine']
        name = f'{engine.capitalize()} {name}'
        sgs = [x['SecurityGroupId'] for x in instance['SecurityGroups']]
        urls = [x['Endpoint']['Address'] for x in instance['CacheNodes']]

        result[name] = {'urls': urls, 'sgs': sgs}

    return result


def get_vpc_name(vpc_id):
    response = Boto().aws('ec2', 'describe_vpcs', VpcIds=[vpc_id])
    vpc_data = response[0]
    name = 'NO-NAME-TAG'
    tags = vpc_data.get('Tags')
    if tags:
        for tag in tags:
            if tag and 'Key' in tag and 'Value' in tag and tag['Key'] == 'Name':
                name = tag['Value']
                break

    return name

def get_a_record(domain):
    resolver = dns.resolver.Resolver()
    resolver.lifetime = resolver.timeout = 10
    found_records = []
    records = []
    error = ''
    try:
        found_records = resolver.resolve(domain, 'A')
    except dns.resolver.NoNameservers:
        error = 'servfail'
    except dns.resolver.NoAnswer:
        error = 'No A records found'
    except dns.resolver.NXDOMAIN:
        error = 'No such domain'
    except Exception as e:
        error = str(e)

    for rec in found_records:
        ip = rec.to_text()
        if not ip in records:
            records.append(ip)

    return [records, error]


def get_redshift_clusters():
    response = Boto().aws('redshift', 'describe_clusters')
    return response


def get_rds_instances():
    rds_instances = Boto().aws('rds', 'describe_db_instances')
    result = {}
    for instance in rds_instances:
        name = instance['DBInstanceIdentifier']
        monitoring_role_arn = instance.get('MonitoringRoleArn')

        roles_list = [re.sub(r'^.*:role/(.+)$', r'\1', x['RoleArn'])
                      for x in instance['AssociatedRoles']]
        if monitoring_role_arn:
            monitoring_role_name = re.sub(
                r'^.*:role/(.+)$', r'\1', monitoring_role_arn)
            roles_list.append(monitoring_role_name)

        sgs = [x['VpcSecurityGroupId'] for x in instance['VpcSecurityGroups']]
        endpoint_url = instance['Endpoint']['Address']
        result[name] = {'url': endpoint_url, 'sgs': sgs, 'roles': roles_list}

    return result


def get_redshift_cluster_info(data, ips):
    name = ''
    for cluster in data:
        cluster_name = cluster['ClusterIdentifier']
        cluster_iam_roles = [
            re.sub(r'^.*:role/(.+)$', r'\1', x['IamRoleArn']) for x in cluster['IamRoles']]

        if 'ClusterNodes' in cluster:
            cluster_ips = [x['PrivateIPAddress']
                           for x in cluster['ClusterNodes']]
            for ip in ips:
                if ip in cluster_ips:
                    name = cluster_name
                    break
        if name:
            break
    return name, cluster_iam_roles


def get_instance_name(instance_id):
    response = Boto().aws('ec2', 'describe_instances',
                          InstanceIds=[instance_id])
    for reservation in response:
        for instance in reservation['Instances']:
            if instance['InstanceId'] == instance_id:
                try:
                    for tag in instance['Tags']:
                        if tag['Key'] == 'Name':
                            return tag['Value']
                except:
                    return ''
    return ''


def get_endpoint_name(vpce_id):
    response = Boto().aws('ec2', 'describe_vpc_endpoints',
                          VpcEndpointIds=[vpce_id])
    service_name = response[0]['ServiceName']
    service_name = re.sub(
        r'^com\.amazonaws\.[^\.]+\.(.+)$', r'\1', service_name)
    return service_name


def get_dms_replication_instances():
    dms_replication_instances = Boto().aws('dms', 'describe_replication_instances')
    result = {}
    for instance in dms_replication_instances:
        name = instance['ReplicationInstanceIdentifier']
        ip = instance['ReplicationInstancePrivateIpAddress']

        result[name] = ip

    return result


def get_sm_endpoint_info(endpoint_name):
    saved_config = []
    em_response = Boto().aws('sagemaker', 'describe_endpoint', EndpointName=endpoint_name)
    config_name = em_response['EndpointConfigName']
    response = Boto().aws('sagemaker', 'describe_endpoint_config',
                          EndpointConfigName=config_name)
    models = [x['ModelName'] for x in response['ProductionVariants']]
    for model_name in models:
        response = Boto().aws('sagemaker', 'describe_model', ModelName=model_name)
        role_name = re.sub(r'^.*:role/(.+)$', r'\1',
                           response['ExecutionRoleArn'])
        data = {'role_name': role_name}
        if 'VpcConfig' in response:
            sgs = response['VpcConfig']['SecurityGroupIds']
            subnets = response['VpcConfig']['Subnets']
            data.update({'sgs': sgs, 'subnets': subnets})
            saved_config.append(data)
    return endpoint_name, saved_config


def get_sm_endpoints():
    saved_endpoints = {}
    endpoints = Boto().aws('sagemaker', 'list_endpoints')
    endpoint_names = [x['EndpointName'] for x in endpoints]
    threads = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        for endpoint_name in endpoint_names:
            threads.append(
                executor.submit(
                    get_sm_endpoint_info,
                    endpoint_name,
                )
            )
        for future in as_completed(threads):
            endpoint_name, data = future.result()
            saved_endpoints[endpoint_name] = data

    return saved_endpoints


def get_possible_sm_endpoints(sm_endpoints, subnet_id, sgs, eni_role_name):
    found_names = []
    for sm_endpoint in sm_endpoints:
        for model_data in sm_endpoints[sm_endpoint]:
            model_sgs = model_data['sgs']
            subnets = model_data['subnets']
            role_name = model_data['role_name']
            if subnet_id in subnets and sgs == model_sgs:
                found_names.append([sm_endpoint, role_name])
                break

    final_found_names = []
    if len(found_names) > 1 and eni_role_name:
        for sm_endpoint, sm_role_name in found_names:
            if not eni_role_name or (eni_role_name and (sm_role_name == eni_role_name)):
                final_found_names.append([sm_endpoint, sm_role_name])

    else:
        final_found_names = found_names

    return final_found_names


def get_eni_role(eni_id):
    end_time = datetime.now() + timedelta(days=1)
    start_time = end_time - timedelta(days=(100))
    response = Boto().aws('cloudtrail',
                          'lookup_events',
                          LookupAttributes=[
                              {
                                  'AttributeKey': 'ResourceName',
                                  'AttributeValue': eni_id,
                              },
                          ],
                          StartTime=start_time,
                          EndTime=end_time
                          )

    found = False
    source_ip = role_name = ''
    for event in response:
        ct_event = json.loads(event['CloudTrailEvent'])
        event_name = ct_event['eventName']
        source_ip = ct_event['sourceIPAddress']
        identity_raw = ct_event['userIdentity']
        invoked_by = identity_raw.get('invokedBy')
        if (not 'errorCode' in ct_event and
                    event_name == 'CreateNetworkInterface'
                ):
            entity_type = identity_raw['sessionContext']['sessionIssuer']['type']
            role_name = identity_raw['sessionContext']['sessionIssuer']['userName']
            break
    return source_ip, role_name


def get_ecs_clusters():
    clusters = Boto().aws('ecs', 'list_clusters')
    return clusters


def get_tasks_info(cluster_name, tasks):
    response = Boto().aws('ecs', 'describe_tasks', cluster=cluster_name, tasks=tasks)
    found_tasks = {}
    for task in response:
        ips = []
        name = ''
        task_definition = task['taskDefinitionArn']
        containers = task.get('containers')
        if containers:
            for cont in containers:
                name = cont['name']
                if not name in found_tasks:
                    found_tasks[name] = {'ips': [],
                                         'task_definition': task_definition}
                ips = [x['privateIpv4Address']
                       for x in cont['networkInterfaces']]

                found_tasks[name]['ips'] += ips
    return found_tasks


def worker(cluster_name, cluster_tasks):
    data = {}
    while cluster_tasks:
        temp_tasks = cluster_tasks[:100]
        tasks_info = get_tasks_info(cluster_name, temp_tasks)
        cluster_tasks = cluster_tasks[100:]
        data.update(tasks_info)
    return cluster_name, data


def get_ecs_info(tasks):
    result = {}
    threads = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        for cluster_name in tasks:
            cluster_tasks = tasks[cluster_name]['tasks']
            threads.append(
                executor.submit(
                    worker,
                    cluster_name,
                    cluster_tasks,
                )
            )

        for future in as_completed(threads):
            cluster_name, data = future.result()
            result[cluster_name] = data

    return result


def get_ecs_clusters_tasks(cluster_arn):
    tasks = Boto().aws('ecs', 'list_tasks', cluster=cluster_arn)
    return cluster_arn, tasks


def get_ecs_tasks(clusters):
    threads = []
    result = {}
    with ThreadPoolExecutor(max_workers=20) as executor:
        for cluster_arn in clusters:
            threads.append(
                executor.submit(
                    get_ecs_clusters_tasks,
                    cluster_arn,
                )
            )

        for future in as_completed(threads):
            cluster_arn, tasks = future.result()
            cluster_name = re.sub(r'^.*:cluster/(.*)$', r'\1', cluster_arn)
            if not cluster_name in result:
                result[cluster_name] = {'tasks': [], 'ips': []}
            result[cluster_name]['tasks'] += tasks

    return result


def get_efs_name(efs_id):
    response = Boto().aws('efs', 'describe_file_systems', FileSystemId=efs_id)
    instance = response['FileSystems'][0]
    name = 'NO-NAME-TAG'
    tags = instance.get('Tags')
    if tags:
        for tag in tags:
            if tag and 'Key' in tag and 'Value' in tag and tag['Key'] == 'Name':
                name = tag['Value']
                break

    return name


def get_neptune_instances():
    neptune_clusters = Boto().aws('rds', 'describe_db_clusters')
    result = {}
    for cluster in neptune_clusters:
        name = cluster['DBClusterIdentifier']
        sgs = [x['VpcSecurityGroupId'] for x in cluster['VpcSecurityGroups']]
        urls = [cluster['Endpoint']]
        roles_list = [re.sub(r'^.*:role/(.+)$', r'\1', x['RoleArn'])
                      for x in cluster['AssociatedRoles']]

        if 'ReaderEndpoint' in cluster:
            urls.append(cluster['ReaderEndpoint'])
        result[name] = {'urls': urls, 'roles': roles_list}

    return result

# Get any Lambdas attached to a Security Group
def run_lambda_action(action_name):
    return action_name, Boto().aws('lambda', action_name, 'NextMarker')

def get_lambdas():

    lambda_client = boto3.client('lambda')

    all_lambdas = []
    next_marker = None
    response = lambda_client.list_functions()
    all_lambdas.append(response)
    while next_marker != '':
      next_marker = ''
      functions = response['Functions']
      if not functions:
        continue

      # Verify if there is next marker
      if 'NextMarker' in response:
        next_marker = response['NextMarker']
        response = lambda_client.list_functions(Marker=next_marker)
        all_lambdas.append(response)
    
    
    return all_lambdas

def get_attached_resources(interfaces, sg_id):

    attached_entities = {}
    saved_redshift_clusters = ''
    saved_rds_instances = ''
    saved_es_instances = ''
    saved_dms_replication_instances = ''
    saved_neptune_clusters = ''
    saved_ecs_clusters = ''
    saved_sm_endpoints = ''
    
    NetworkInterfaces = []
    Lambda_ips = [] # get list of IPs for lambdas sharing same security group

    for eni in interfaces:
        
        description = eni['Description']
        int_type = eni['InterfaceType']
        eni_id = eni['NetworkInterfaceId']
        sgs = [x['GroupId']+' ('+x['GroupName']+')' for x in eni['Groups']]
        sgs_list = [x['GroupId'] for x in eni['Groups']]
        subnet_id = eni['SubnetId']

        private_ips = []
        for temp_eni in eni['PrivateIpAddresses']:
            private_ip = temp_eni['PrivateIpAddress']
            private_ips.append(private_ip)

        all_eni_ips = private_ips

        # Get any Network Interfaces a Security Group is attached to
        if eni_id is not None:
          NetworkInterfaces.append(eni_id)

        requester_id = eni.get('RequesterId')
        status = eni.get('Status')
        managed = eni.get('RequesterManaged')
        attachment = eni.get('Attachment')
        instance_id = ''

        if attachment:
            instance_id = attachment.get('InstanceId')

        private_ips_str = ', '.join(private_ips)
        name = service = ''

        if int_type == 'lambda':
            name = re.sub(
                r'^AWS Lambda VPC ENI\-(.+)\-[^\-]+\-[^\-]+\-[^\-]+\-[^\-]+\-[^\-]+$', r'\1', description)
            service = 'Lambda Function'
            Lambda_ips += private_ips

        elif int_type == 'nat_gateway':
            service = 'NAT Gateway'
            name = re.sub(r'^Interface for NAT Gateway (.+)$',
                          r'\1', description)
        elif requester_id == 'amazon-elasticache':
            service = 'Elasticache'
            if not saved_es_instances:
                saved_es_instances = get_elasticache_instances()

            resolve_success = False
            found_any = False
            url = ''
            for es_name in saved_es_instances:
                urls = saved_es_instances[es_name]['urls']
                es_sgs = saved_es_instances[es_name]['sgs']
                found_sg = False
                for sg in es_sgs:
                    for saved_sg in sgs:
                        if saved_sg.startswith(sg+' '):
                            found_sg = True
                            break
                    if found_sg:
                        break
                if found_sg:
                    found_any = True
                    found_match = False
                    for url in urls:
                        found_ips, error = get_a_record(url)
                        if found_ips:
                            resolve_success = True

                        for found_ip in found_ips:
                            if found_ip in all_eni_ips:
                                found_match = True
                                break
                        if found_match:
                            break
                    if found_match:
                        name = es_name
                        break

        elif requester_id == 'amazon-redshift':
            if not saved_redshift_clusters:
                saved_redshift_clusters = get_redshift_clusters()

            service = 'Redshift'
            name, cluster_iam_roles = get_redshift_cluster_info(
                saved_redshift_clusters, all_eni_ips)
        elif requester_id == 'amazon-rds':
            service = 'RDS'
            name = ''
            if not saved_rds_instances:
                saved_rds_instances = get_rds_instances()
            resolve_success = False
            found_any = False
            url = ''
            for db_name in saved_rds_instances:
                url = saved_rds_instances[db_name]['url']
                db_sgs = saved_rds_instances[db_name]['sgs']
                roles = saved_rds_instances[db_name]['roles']
                found_sg = False
                for sg in db_sgs:
                    for saved_sg in sgs:
                        if saved_sg.startswith(sg+' '):
                            found_sg = True
                            break
                    if found_sg:
                        break
                if found_sg:
                    found_any = True
                    found_ips, error = get_a_record(url)
                    if found_ips:
                        resolve_success = True
                    found_match = False
                    for found_ip in found_ips:
                        if found_ip in all_eni_ips:
                            found_match = True
                            break
                    if found_match:
                        name = db_name
            if found_any and not resolve_success:
                print_red(f'DNS Error: {url}')

        elif instance_id:
            service = 'EC2'
            instance_name = get_instance_name(instance_id)
            name = f'{instance_id} ({instance_name})'

        elif int_type == 'vpc_endpoint':
            service = 'VPC Endpoint'
            vpce_id = re.sub(r'^VPC Endpoint Interface (.+)$',
                             r'\1', description)
            name = get_endpoint_name(vpce_id)

        elif requester_id == '237081731433':
            service = 'DMS'
            name = ''
            if not saved_dms_replication_instances:
                saved_dms_replication_instances = get_dms_replication_instances()

            for dms_name in saved_dms_replication_instances:
                dms_instance_ip = saved_dms_replication_instances[dms_name]
                if dms_instance_ip in all_eni_ips:
                    name = dms_name

        elif requester_id == '070621534519':
            service = 'Sagemaker Endpoint'
            if status != 'available':
                if not saved_sm_endpoints:
                    saved_sm_endpoints = get_sm_endpoints()
                source_ip, eni_role_name = get_eni_role(eni_id)
                possible_endpoints = get_possible_sm_endpoints(
                    saved_sm_endpoints, subnet_id, sgs_list, eni_role_name)
                possible_endpoints_names = [x[0] for x in possible_endpoints]
                name = ' OR '.join(possible_endpoints_names)
            else:
                name = ''

        elif requester_id == 'amazon-elb':
            if re.match(r'^ELB app\/.*$', description):
                service = 'ALB'
                name = re.sub(r'^ELB app\/([^\/]+).*$', r'\1', description)
            elif re.match(r'^ELB (.*)$', description):
                service = 'Classic ELB'
                name = re.sub(r'^ELB (.*)$', r'\1', description)
            else:
                service = 'Unusual ELB'
                name = description
        elif int_type == 'network_load_balancer':
            service = 'NLB'
            name = re.sub(r'^ELB net\/([^\/]+).*$', r'\1', description)

        elif managed and 'arn:aws:ecs' in description:
            service = 'ECS'
            name = ''
            if not saved_ecs_clusters:
                ecs_clusters = get_ecs_clusters()
                ecs_tasks = get_ecs_tasks(ecs_clusters)
                saved_ecs_clusters = get_ecs_info(ecs_tasks)

            for cluster_name in saved_ecs_clusters:
                for task_name in saved_ecs_clusters[cluster_name]:
                    for ip in saved_ecs_clusters[cluster_name][task_name]['ips']:
                        if ip in all_eni_ips:
                            name = f'{cluster_name}/{task_name}'
                            break
                    if name:
                        break
                if name:
                    break

        elif managed and 'EFS mount target for ' in description:
            service = 'EFS'
            efs_id = description.replace('EFS mount target for ', '')
            efs_id = re.sub(r'^(\S+) .*$', r'\1', efs_id)
            name = get_efs_name(efs_id)

        elif managed and re.match(r'^.*arn:aws:sagemaker:.*:notebook-instance\/([^\]]+).*$', description):
            service = 'Sagemaker Notebook'
            name = re.sub(
                r'^.*arn:aws:sagemaker:.*:notebook-instance\/([^\]]+).*$', r'\1', description)

        elif managed and description == 'RDSNetworkInterface':
            service = 'NeptuneDB'
            if not saved_neptune_clusters:
                saved_neptune_clusters = get_neptune_instances()

            resolve_success = False
            found_any = False
            url = ''
            name = ''
            for cluster_name in saved_neptune_clusters:
                urls = saved_neptune_clusters[cluster_name]['urls']
                found_any = True
                for url in urls:
                    found_ips, error = get_a_record(url)
                    if found_ips:
                        resolve_success = True
                    found_match = False
                    for found_ip in found_ips:
                        if found_ip in all_eni_ips:
                            found_match = True
                            break
                    if found_match:
                        name = cluster_name
                        break
                    if found_match:
                        break

            if found_any and not resolve_success:
                print_red(f'DNS Error: {url}')

        elif re.match(r'^.*Amazon MSK network interface for cluster arn:aws:kafka:.*:cluster\/([^\/]+)\/.*$', description):
            service = 'Kafka'
            name = re.sub(
                r'^.*Amazon MSK network interface for cluster arn:aws:kafka:.*:cluster\/([^\/]+)\/.*$', r'\1', description)
        elif description.startswith('Amazon EKS '):
            service = 'EKS'
            name = re.sub(r'^Amazon EKS (.+)$', r'\1', description)

        elif status == 'available':
            service = 'Unused'
            name = description
        else:
            service = 'Unknown'
            name = description

        # Create list of Attached Resources
        full_res_name = f'{service} {name}'
        
        if not full_res_name in attached_entities:
            attached_entities[full_res_name] = {
                'service': service, 'name': name, 'ips': private_ips}
        else:
            attached_entities[full_res_name]['ips'] += private_ips
    
    # Add Lambdas - if any - to Attached Resources
    all_lambdas = get_lambdas()
    
    all_functions = []
    
    for lambdas in all_lambdas:
      all_functions = lambdas['Functions']
    
      for lambda_funtion in all_functions:
       
        # If no VpcConfig in the lambda Function - skip it
        if 'VpcConfig' in lambda_funtion:
          Function_Name = lambda_funtion['FunctionName']
          Security_Groups = lambda_funtion['VpcConfig']['SecurityGroupIds']

          if sg_id in Security_Groups:
            service = 'Lambda Function'
            name = Function_Name
            
            full_res_name = f'{service} {name}'
            if full_res_name not in attached_entities:
              attached_entities[full_res_name] = {'service': service, 'name': name, 'ips': Lambda_ips}
            else:
              for private_ip in private_ips:
                  if private_ip not in Lambda_ips:
                    attached_entities[full_res_name]['ips'] += private_ips
    
    # Add Network Interfaces - if any - to Attached Resources
    if NetworkInterfaces is not None and len(NetworkInterfaces) > 0:
      attached_entities['Network Interfaces'] = {'service': 'Network Interface', 'name': 'ENIs', 'ips': NetworkInterfaces}

    return attached_entities


def run_ec2_action(action_name):
    return action_name, Boto().aws('ec2', action_name)


def get_interfaces_and_sgs():
    threads = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        threads.append(executor.submit(run_ec2_action, 'describe_security_groups'))
        threads.append(executor.submit(run_ec2_action, 'describe_network_interfaces'))

        for future in as_completed(threads):
            action_name, data = future.result()
            if action_name == 'describe_security_groups':
                all_sgs = data
            elif action_name == 'describe_network_interfaces':
                all_ec2_interfaces = data

    return all_ec2_interfaces, all_sgs

def main():

    if len(sys.argv) < 2:
        all_sgs = Boto().aws('ec2', 'describe_security_groups')
        sgs_list = []
        for sg in all_sgs:
            sg_id = sg['GroupId']
            sg_name = sg['GroupName']
            sgs_list.append([sg_id, sg_name])

        max_id = max([len(x[0]) for x in sgs_list])
        for sg_id, sg_name in sgs_list:
            print('%-*s - %s' % (max_id, sg_id, sg_name))

        return
    sg_id = sys.argv[1]
    if not sg_id.startswith('sg-'):
        print_red('Error: SG ID must start with sg-')
        return

    if len(sys.argv) > 2 and sys.argv[2] == '-c':
        cache = True
        all_sgs = load_data('/tmp/sgs.pickle')
        all_ec2_interfaces = load_data('/tmp/ec2_interfaces.pickle')
    else:
        cache = False
        all_ec2_interfaces, all_sgs = get_interfaces_and_sgs()
        
        save_data('/tmp/ec2_interfaces.pickle', all_ec2_interfaces)
        save_data('/tmp/sgs.pickle', all_sgs)

    sgs_names = {x['GroupId']: x['GroupName'] for x in all_sgs}
    sg_data = [x for x in all_sgs if x['GroupId'] == sg_id]
    if not sg_data:
        print_red(f'Error: Security Group {sg_id} does NOT exist')
        return

    sg_data = sg_data[0]
    sg_name = sg_data['GroupName']
    vpc_id = sg_data.get('VpcId')
    sg_description = sg_data.get('Description')
    if vpc_id:
        vpc_name = get_vpc_name(vpc_id)
        vpc_full_name = f'{vpc_id} ({vpc_name})'
    else:
        vpc_full_name = ''

    full_sg_name = f'{sg_id} ({sg_name})'

    print_blue('Security Group Name : ', nl=False)
    print_green(sg_name)
    print_blue('VPC                 : ',nl=False)
    if not vpc_full_name:
        print_yellow('EC2 Classic')
    else:
        print_green(vpc_full_name)
    print_blue('Description         : ',nl=False)
    print_green(sg_description)
    print()


    sg_interfaces = [x for x in all_ec2_interfaces if sg_id in [
        y['GroupId'] for y in x['Groups']]]
    
    attached_resources = get_attached_resources(sg_interfaces, sg_id)

    if attached_resources:
        print_blue('Attached to Resources: ')
        for res in attached_resources:
            service = attached_resources[res]['service']
            name = attached_resources[res]['name']
            ips = attached_resources[res]['ips']
            ips_str = ', '.join(ips)
            print(f'\t{turn_blue(service)} {turn_green(name)} - {ips_str}')
        print()
    else:
        print_yellow('Not attached to any resources\n')

    inbound_rules_raw = sg_data['IpPermissions']
    inbound_rules = get_rules(inbound_rules_raw, sgs_names)
    if inbound_rules:
        print_blue('Inbound Rules:')
        print_rules(inbound_rules)
    else:
        print_yellow('No Inbound rules')
    print()

    outbound_rules_raw = sg_data['IpPermissionsEgress']
    outbound_rules = get_rules(outbound_rules_raw, sgs_names)
    if outbound_rules:
        print_blue('Outbound Rules:')
        print_rules(outbound_rules)
    else:
        print_yellow('No Outbound rules')
    print()

    referenced_sgs = get_referenced_sgs(full_sg_name, all_sgs, sgs_names)

    if referenced_sgs:
        print_blue('Referenced in SGs:')
        for ref_sg in referenced_sgs:
            ref_sg_id = referenced_sgs[ref_sg]
            print(f'\t- {ref_sg}', end='')
            ref_sg_interfaces = [x for x in all_ec2_interfaces if ref_sg_id in [
                y['GroupId'] for y in x['Groups']]]
            ref_attached_resources = get_attached_resources(ref_sg_interfaces, sg_id)
            ref_sg_data = [x for x in all_sgs if x['GroupId'] == ref_sg_id][0]
            ref_inbound_rules_raw = ref_sg_data['IpPermissions']
            ref_inbound_rules = get_rules(ref_inbound_rules_raw, sgs_names)
            ref_outbound_rules_raw = ref_sg_data['IpPermissionsEgress']
            ref_outbound_rules = get_rules(ref_outbound_rules_raw, sgs_names)
            saved_ref_inbound_rules = []
            saved_ref_outbound_rules = []
            for rule in ref_inbound_rules:
                if rule[1] == full_sg_name:
                    saved_ref_inbound_rules.append(rule)

            for rule in ref_outbound_rules:
                if rule[1] == full_sg_name:
                    saved_ref_outbound_rules.append(rule)

            if not ref_attached_resources:
                print_yellow(' - No attached resources')
            else:
                print()
                for res in ref_attached_resources:
                    service = ref_attached_resources[res]['service']
                    name = ref_attached_resources[res]['name']
                    ips = ref_attached_resources[res]['ips']
                    ips_str = ', '.join(ips)
                    print(f'\t\t{turn_blue(service)} {turn_green(name)} - {ips_str}')
                print()
            print_rules(saved_ref_inbound_rules, 'Inbound')
            print_rules(saved_ref_outbound_rules, 'Outbound')
            print()

    else:
        print_yellow('No references in other SGs')

    print()


# -----------------------------------------------
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print_red("\r  \nInterrupted by Ctrl+C\n")


#!/usr/bin/env python
import sys
import re
import json
import boto3
import botocore
import csv
import dns.resolver
from netaddr import IPNetwork, IPAddress
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from datetime import datetime, timedelta, timezone



def print_blue(message, nl=True):
    if nl:
        print("\033[1;34;40m%s\033[1;37;40m" % message)
    else:
        print("\033[1;34;40m%s\033[1;37;40m" % message, end='')
        sys.stdout.flush()


def print_green(message):
    print("\033[1;32;40m%s\033[1;37;40m" % message)


def print_yellow(message):
    print("\033[1;33;40m%s\033[1;37;40m" % message)


def print_red(message):
    print("\033[1;31;40m%s\033[1;37;40m" % message)

# ===============================================

boto_clients = {}
def get_client(service_name):
    client_service = boto_clients.get(service_name)
    if not client_service:
        client_service = boto3.client(service_name)
        boto_clients[service_name] = client_service
    return client_service

aws_cache = {}
def aws(service_name, function_name, quiet=False,cache=True, **kwargs):
    full_req_name = f'{service_name}:{function_name}:{kwargs}'
    if cache and full_req_name in aws_cache:
        return aws_cache[full_req_name]
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

    }
    next_token_key_names = ['NextMarker', 'NextToken', 'Marker', 'nextToken']

    object_list = []
    token_name=''

    func_full_name = f'{service_name}:{function_name}'
    

    if func_full_name in aws_functions_dict:
        func_dict = aws_functions_dict[func_full_name]
        token_name = func_dict.get('token_name')
        max_name = func_dict.get('max_name')
        max_items = func_dict.get('max_items')
        no_max_args = func_dict['no_max_args'] if 'no_max_args' in func_dict else []
        if max_name and not (set(list(kwargs.keys())) & set(no_max_args)):
            kwargs[max_name] = max_items


    client = get_client(service_name)
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
            sleep(throttle_wait_ms)
            continue
        except client.exceptions.ClientError as err:
            if err.response['Error']['Code'] == 'Throttling':
                throttle_count += 1
                throttle_wait_ms = 2**throttle_count/10
                sleep(throttle_wait_ms)
                continue
            else:
                err_msg = err.response['Error']['Message']
                if not quiet:
                    print_red(f'Error running {full_req_name} - {err_msg}')
                return []

        # get first element in response dict
        first_elem = response[list(response.keys())[0]]
        if not isinstance(first_elem, list):
            aws_cache[full_req_name] = response
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

    aws_cache[full_req_name] = object_list
    return object_list

# ---------------------------------------


def get_instance_info(instance_id):
    response = aws('ec2', 'describe_instances', InstanceIds=[instance_id])
    for reservation in response:
        for instance in reservation['Instances']:
            role_name = instance['IamInstanceProfile']['Arn'] if 'IamInstanceProfile' in instance else ''
            role_name = re.sub(r'^.*:instance-profile/(.+)$',r'\1',role_name)
            if not role_name:
                role_name = ''

            if instance['InstanceId'] == instance_id:
                try:
                    for tag in instance['Tags']:
                        if tag['Key'] == 'Name':
                            return role_name,tag['Value']
                except:
                    return role_name,'NO-NAME-TAG'
    return '',''


def get_subnet_info(subnet_id):
    response = aws('ec2', 'describe_subnets', SubnetIds=[subnet_id])
    if not response:
        return {}
    subnet_data = response[0]
    name = 'NO-NAME-TAG'
    cidr = subnet_data['CidrBlock']
    az = subnet_data['AvailabilityZone']
    tags = subnet_data.get('Tags')
    if tags:
        for tag in tags:
            if tag and 'Key' in tag and 'Value' in tag and tag['Key'] == 'Name':
                name = tag['Value']
                break

    return {'name': name, 'cidr': cidr, 'az': az}


def get_vpc_name(vpc_id):
    response = aws('ec2', 'describe_vpcs', VpcIds=[vpc_id])
    vpc_data = response[0]
    name = 'NO-NAME-TAG'
    tags = vpc_data.get('Tags')
    if tags:
        for tag in tags:
            if tag and 'Key' in tag and 'Value' in tag and tag['Key'] == 'Name':
                name = tag['Value']
                break

    return name


def get_endpoint_name(vpce_id):
    response = aws('ec2', 'describe_vpc_endpoints', VpcEndpointIds=[vpce_id])
    service_name = response[0]['ServiceName']
    service_name = re.sub(
        r'^com\.amazonaws\.[^\.]+\.(.+)$', r'\1', service_name)
    return service_name


def get_redshift_clusters():
    response = aws('redshift', 'describe_clusters')
    return response


def get_rds_instances():
    rds_instances = aws('rds', 'describe_db_instances')
    result = {}
    for instance in rds_instances:
        name = instance['DBInstanceIdentifier']
        monitoring_role_arn = instance.get('MonitoringRoleArn')
        
        roles_list = [re.sub(r'^.*:role/(.+)$',r'\1',x['RoleArn']) for x in instance['AssociatedRoles']]
        if monitoring_role_arn:
            monitoring_role_name = re.sub(r'^.*:role/(.+)$',r'\1',monitoring_role_arn)
            roles_list.append(monitoring_role_name)

        sgs = [x['VpcSecurityGroupId'] for x in instance['VpcSecurityGroups']]
        endpoint_url = instance['Endpoint']['Address']
        result[name] = {'url': endpoint_url, 'sgs': sgs,'roles':roles_list}

    return result


def get_neptune_instances():
    neptune_clusters = aws('rds', 'describe_db_clusters')
    result = {}
    for cluster in neptune_clusters:
        name = cluster['DBClusterIdentifier']
        sgs = [x['VpcSecurityGroupId'] for x in cluster['VpcSecurityGroups']]
        urls = [cluster['Endpoint']]
        roles_list = [re.sub(r'^.*:role/(.+)$',r'\1',x['RoleArn']) for x in cluster['AssociatedRoles']]

        if 'ReaderEndpoint' in cluster:
            urls.append(cluster['ReaderEndpoint'])
        result[name] = {'urls': urls,'roles':roles_list}

    return result


def get_elasticache_instances():
    es_instances = aws(
        'elasticache', 'describe_cache_clusters', ShowCacheNodeInfo=True)
    result = {}
    for instance in es_instances:
        name = instance['CacheClusterId']
        engine = instance['Engine']
        name = f'{engine.capitalize()} {name}'
        sgs = [x['SecurityGroupId'] for x in instance['SecurityGroups']]
        urls = [x['Endpoint']['Address'] for x in instance['CacheNodes']]

        result[name] = {'urls': urls, 'sgs': sgs}

    return result


def get_dms_replication_instances():
    dms_replication_instances = aws('dms', 'describe_replication_instances')
    result = {}
    for instance in dms_replication_instances:
        name = instance['ReplicationInstanceIdentifier']
        ip = instance['ReplicationInstancePrivateIpAddress']

        result[name] = ip

    return result


def get_redshift_cluster_info(data, ips):
    name = ''
    for cluster in data:
        cluster_name = cluster['ClusterIdentifier']
        cluster_iam_roles = [re.sub(r'^.*:role/(.+)$',r'\1',x['IamRoleArn']) for x in cluster['IamRoles']]

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


def get_efs_name(efs_id):
    response = aws('efs', 'describe_file_systems', FileSystemId=efs_id)
    instance = response['FileSystems'][0]
    name = 'NO-NAME-TAG'
    tags = instance.get('Tags')
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


def get_ecs_clusters():
    clusters = aws('ecs', 'list_clusters')
    return clusters


def get_tasks_info(cluster_name, tasks):
    response = aws('ecs', 'describe_tasks', cluster=cluster_name, tasks=tasks)
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
                    found_tasks[name] = {'ips':[],'task_definition':task_definition}
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


def get_vpcs():
    response = aws('ec2', 'describe_vpcs')
    vpcs = {}
    for vpc_data in response:
        vpc_id = vpc_data['VpcId']
        name = 'NO-NAME-TAG'
        tags = vpc_data.get('Tags')
        if tags:
            for tag in tags:
                if tag and 'Key' in tag and 'Value' in tag and tag['Key'] == 'Name':
                    name = tag['Value']
                    break
        vpcs[vpc_id] = name

    return vpcs


def get_subnets():
    subnets = aws('ec2', 'describe_subnets')
    result = {}
    for subnet in subnets:
        subnet_id = subnet['SubnetId']
        cidr = subnet['CidrBlock']
        az = subnet['AvailabilityZone']
        vpc_id = subnet['VpcId']
        tags = subnet.get('Tags')
        name = 'NO-NAME-TAG'
        if tags:
            for tag in tags:
                if tag and 'Key' in tag and 'Value' in tag and tag['Key'] == 'Name':
                    name = tag['Value']
                    break
        result[subnet_id] = {'cidr': cidr, 'az': az,
                             'name': name, 'vpc_id': vpc_id}
    return result


def get_ecs_clusters_tasks(cluster_arn):
    tasks = aws('ecs', 'list_tasks', cluster=cluster_arn)
    return cluster_arn, tasks


def get_ips_in_subnets(subnets):
    interfaces = aws('ec2', 'describe_network_interfaces', Filters=[
                     {'Name': 'subnet-id', 'Values': subnets}])
    return interfaces


def get_all_enis():
    interfaces = aws('ec2', 'describe_network_interfaces')
    return interfaces


def get_sm_endpoint_info(endpoint_name):
    saved_config = []
    em_response = aws('sagemaker','describe_endpoint',EndpointName=endpoint_name)
    config_name = em_response['EndpointConfigName']
    response = aws('sagemaker','describe_endpoint_config',EndpointConfigName=config_name)
    models = [x['ModelName'] for x in response['ProductionVariants']]
    for model_name in models:
        response = aws('sagemaker','describe_model',ModelName=model_name)
        role_name = re.sub(r'^.*:role/(.+)$',r'\1',response['ExecutionRoleArn'])
        data = {'role_name':role_name}
        if 'VpcConfig' in response:
            sgs = response['VpcConfig']['SecurityGroupIds']
            subnets = response['VpcConfig']['Subnets']
            data.update({'sgs':sgs,'subnets':subnets})
            saved_config.append(data)
    return endpoint_name,saved_config


def get_sm_endpoints():
    saved_endpoints = {}
    endpoints = aws('sagemaker','list_endpoints')
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

def get_possible_sm_endpoints(sm_endpoints,subnet_id,sgs,eni_role_name):
    found_names = []
    for sm_endpoint in sm_endpoints:
        for model_data in sm_endpoints[sm_endpoint]:
            model_sgs = model_data['sgs']
            subnets = model_data['subnets']
            role_name = model_data['role_name']
            if subnet_id in subnets and sgs==model_sgs:
                found_names.append([sm_endpoint,role_name])
                break

    final_found_names = []
    if len(found_names)>1 and eni_role_name:
        for sm_endpoint,sm_role_name in found_names:
            if not eni_role_name or (eni_role_name and (sm_role_name == eni_role_name)):
                final_found_names.append([sm_endpoint,sm_role_name])

    else:
        final_found_names = found_names


    return final_found_names


def get_eni_role(eni_id):
    end_time = datetime.now() + timedelta(days=1)
    start_time = end_time - timedelta(days=(100))
    response = aws('cloudtrail',
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
            event_name=='CreateNetworkInterface'
            ):
            entity_type = identity_raw['sessionContext']['sessionIssuer']['type']
            role_name = identity_raw['sessionContext']['sessionIssuer']['userName']
            break
    return source_ip,role_name


def get_role_from_task_definition(task_definition_arn):
    response = aws('ecs','describe_task_definition',taskDefinition=task_definition_arn)
    role_arn = response['taskDefinition']['taskRoleArn']
    role_name = re.sub(r'^.*:role/(.+)$',r'\1',role_arn)
    return role_name


def get_lambda_role(function_name):
    response = aws('lambda','get_function_configuration',FunctionName=function_name)
    role_arn = response['Role']
    role_name = re.sub(r'^.*:role/(.+)$',r'\1',role_arn)
    role_name = re.sub(r'^service\-role/(.*)$',r'\1',role_name)
    return role_name

def get_eks_role(cluster_name):
    response = aws('eks','describe_cluster',name=cluster_name)
    role_arn = response['cluster']['roleArn']
    role_name = re.sub(r'^.*:role/(.+)$',r'\1',role_arn)
    return role_name

def get_sm_notebook_role(name):
    response = aws('sagemaker','describe_notebook_instance',NotebookInstanceName=name)
    role_name =''
    if response:
        role_arn = response['RoleArn']
        role_name = re.sub(r'^.*:role/(.+)$',r'\1',role_arn)
    return role_name


def pretty_date(time):
    """Get pretty past time since input date"""
    now = datetime.utcnow().replace(
        tzinfo=timezone.utc,
    ).astimezone(tz=None)
    diffSeconds = now-time
    diffSeconds = diffSeconds.total_seconds()
    intervals = (
        ('years', 31536000),
        ('days', 86400),
    )
    result = []
    for name, count in intervals:
        value = diffSeconds // count
        if value:
            diffSeconds -= value*count
            if value == 1:
                name = name.rstrip('s')
            result.append('{} {}'.format(int(value), name))
    output = ', '.join(result[:2])
    if output == '':
        output = '0 days'
    return output

def get_deleted_eni_data(eni_id):
    end_time = datetime.now() + timedelta(days=1)
    start_time = end_time - timedelta(days=(100))
    response = aws('cloudtrail',
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
    
    data = {}
    for event in response:
        ct_event = json.loads(event['CloudTrailEvent'])
        event_name = ct_event['eventName']
        if (not 'errorCode' in ct_event and event_name=='CreateNetworkInterface'):
            data = ct_event['responseElements']['networkInterface']
            
            for key in list(data.keys()):
                cap_key = key[0].capitalize() + key[1:]
                data[cap_key] = data[key]

            data['Status'] = 'Deleted'
            data['InterfaceType'] = data.get('Interfacetype')
            
            temp_groups = data.get('groupSet')['items']
            sgs = []
            for sg in temp_groups:
                sgs.append({'GroupId':sg['groupId'],'GroupName':sg['groupName']})

            data['Groups'] = sgs

            temp_ips = data.get('privateIpAddressesSet')['item']
            ips = []
            for ip in temp_ips:
                ips.append({'PrivateIpAddress':ip['privateIpAddress']})

            data['PrivateIpAddresses'] = ips
            
            break
    return data
    

def main():
    if len(sys.argv) < 2:
        print("Command: %s <ENI/IP> \n" % sys.argv[0])
        return

    ips = sys.argv[1:]
    data_type = ''
    saved_subnets = {}
    saved_vpcs = {}
    saved_redshift_clusters = ''
    saved_rds_instances = ''
    saved_es_instances = ''
    saved_dms_replication_instances = ''
    saved_neptune_clusters = ''
    saved_ecs_clusters = ''
    saved_sm_endpoints = ''
    output_type = 'verbose'

    if ips[0] == 'all':
        output_type = 'all'
        all_enis = get_all_enis()
        saved_subnets = get_subnets()
        saved_vpcs = get_vpcs()
        output_file_name = f'eni-output.csv'
        output_csv_file = open(output_file_name, mode='w')
        output_csv_writer = csv.writer(
            output_csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

    else:
        all_enis = []
        for input_ip in ips:
            if re.match(r'^eni\-', input_ip):
                data_type = 'eni'
            elif re.match(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', input_ip):
                data_type = 'ip'
            else:
                print_red(f'Error: {input_ip} is in Wrong format\n')
                if len(ips) > 1:
                    print('-'*40)
                continue

            if data_type == 'eni':
                enis_raw = aws('ec2', 'describe_network_interfaces',
                               quiet=True, NetworkInterfaceIds=[input_ip])

            else:
                enis_raw = aws('ec2', 'describe_network_interfaces', quiet=True, Filters=[
                               {'Name': 'addresses.private-ip-address', 'Values': [input_ip]}])
                if not enis_raw:
                    enis_raw = aws('ec2', 'describe_network_interfaces', quiet=True, Filters=[
                                   {'Name': 'addresses.association.public-ip', 'Values': [input_ip]}])

            if not enis_raw:
                if data_type == 'eni':
                    print_yellow(f'ENI {input_ip} not found, looking in cloudtrail logs...')
                    enis_raw = get_deleted_eni_data(input_ip)
                    if not enis_raw:
                        print_red('ENI not found!')
                        if len(ips) > 1:
                            print('-'*40)
                        continue
                    else:
                        all_enis += [enis_raw]
                if not enis_raw:
                    print_yellow(f'IP address {input_ip} not found. Looking for Subnets..')
                    all_subnets = get_subnets()
                    found_subnet_ids = {}
                    for subnet_id in all_subnets:
                        if IPAddress(input_ip) in IPNetwork(all_subnets[subnet_id]['cidr']):
                            found_subnet_ids[subnet_id] = all_subnets[subnet_id]

                    if not found_subnet_ids:
                        print_red(f'No matching Subnets found')
                        if len(ips) > 1:
                            print('-'*40)
                        continue

                    enis = get_ips_in_subnets(list(found_subnet_ids.keys()))
                    all_enis += enis
                    print(f'Found {len(enis)} IPs in {len(found_subnet_ids)} subnets')

                    for subnet_id in found_subnet_ids:
                        if not subnet_id in saved_subnets:
                            saved_subnets[subnet_id] = get_subnet_info(subnet_id)

                        subnet_info = saved_subnets[subnet_id]
                        subnet_name = subnet_info.get('name')
                        cidr = subnet_info.get('cidr')
                        az = subnet_info.get('az')
                        vpc_id = found_subnet_ids[subnet_id]['vpc_id']
                        if not vpc_id in saved_vpcs:
                            saved_vpcs[vpc_id] = get_vpc_name(vpc_id)
                        vpc_name = saved_vpcs[vpc_id]

                        print_blue('Subnet    : ', nl=False)
                        print(f'{subnet_id} ({subnet_name})')
                        print_blue('VPC       : ', nl=False)
                        print(f'{vpc_id} ({vpc_name})')
                        print_blue('CIDR      : ', nl=False)
                        print(cidr)
                        print_blue('AZ        : ', nl=False)
                        print(az)
                        print()

                        output_type = 'quick'
            else:
                all_enis += enis_raw

    first_run = True
    count = 0
    for eni in all_enis:
        eni_role_name = ''
        description = eni['Description']
        int_type = eni['InterfaceType']
        eni_id = eni['NetworkInterfaceId']
        sgs = [x['GroupId']+' ('+x['GroupName']+')' for x in eni['Groups']]
        sgs_list = [x['GroupId'] for x in eni['Groups']]
        sgs_str = ', '.join(sgs)


        subnet_id = eni['SubnetId']
        if not subnet_id in saved_subnets:
            saved_subnets[subnet_id] = get_subnet_info(subnet_id)

        subnet_info = saved_subnets[subnet_id]
        subnet_name = subnet_info.get('name')
        cidr = subnet_info.get('cidr')
        az = subnet_info.get('az')
        vpc_id = eni['VpcId']
        if not vpc_id in saved_vpcs:
            saved_vpcs[vpc_id] = get_vpc_name(vpc_id)

        vpc_name = saved_vpcs[vpc_id]
        private_ips = []
        public_ips = []
        for temp_eni in eni['PrivateIpAddresses']:
            private_ip = temp_eni['PrivateIpAddress']
            private_ips.append(private_ip)
            if 'Association' in temp_eni and 'PublicIp' in temp_eni['Association']:
                public_ips.append(temp_eni['Association']['PublicIp'])

        all_eni_ips = private_ips + public_ips

        requester_id = eni.get('RequesterId')
        status = eni.get('Status')
        managed = eni.get('RequesterManaged')
        attachment = eni.get('Attachment')
        instance_id = ''
        launch_time_str = launched_days_ago = ''
        if attachment:
            instance_id = attachment.get('InstanceId')
            if 'AttachTime' in attachment:
                launch_time = attachment['AttachTime']
                launch_time_str = launch_time.strftime('%F')
                launched_days_ago = pretty_date(launch_time) 
            else:
                launch_time_str=launched_days_ago=''

        private_ips_str = ', '.join(private_ips)
        public_ips_str = ', '.join(public_ips)
        name = service = ''

        if int_type == 'lambda':
            name = re.sub(
                r'^AWS Lambda VPC ENI\-(.+)\-[^\-]+\-[^\-]+\-[^\-]+\-[^\-]+\-[^\-]+$', r'\1', description)
            eni_role_name = get_lambda_role(name)
            service = 'Lambda Function'

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
            name, cluster_iam_roles = get_redshift_cluster_info(saved_redshift_clusters, all_eni_ips)
            eni_role_name = ', '.join(cluster_iam_roles)
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
                        eni_role_name = ', '.join(roles)

            
            if found_any and not resolve_success:
                print_red(f'DNS Error: {url}')

        elif instance_id:
            service = 'EC2'
            eni_role_name,instance_name = get_instance_info(instance_id)

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
            if status!='available':
                if not saved_sm_endpoints:
                    saved_sm_endpoints = get_sm_endpoints()
                source_ip,eni_role_name = get_eni_role(eni_id)
                possible_endpoints = get_possible_sm_endpoints(saved_sm_endpoints,subnet_id,sgs_list,eni_role_name)
                possible_endpoints_names = [x[0] for x in possible_endpoints]
                possible_roles = [x[1] for x in possible_endpoints]
                if possible_roles:
                    if len(possible_roles)==1 or not eni_role_name:
                        eni_role_name = ' OR '.join(possible_roles)
                
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
                            task_definition = saved_ecs_clusters[cluster_name][task_name]['task_definition'] 
                            eni_role_name = get_role_from_task_definition(task_definition)
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

            eni_role_name = get_sm_notebook_role(name)

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
                cluster_iam_roles = saved_neptune_clusters[cluster_name]['roles']
                eni_role_name = ', '.join(cluster_iam_roles)
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
            eni_role_name = get_eks_role(name)

        elif status == 'available':
            service = 'Unused'
            name = description
        else:
            service = 'Unknown'
            name = description

        if output_type == 'verbose':
            print_blue('Service   : ', nl=False)
            print_green(service)
            print_blue('Name      : ', nl=False)
            if not name:
                print_red('NOT FOUND')
            else:
                print_green(name)
            if service in ['EC2','ECS','Redshift','RDS','Lambda Function','Sagemaker Endpoint','Sagemaker Notebook','NeptuneDB','EKS']:
                print_blue('Role Name : ', nl=False)
                if eni_role_name:
                    print_green(eni_role_name)
                else:
                    print_red('No Role')
            print_blue('Status    : ', nl=False)
            if status!='in-use':
                print_red(status)
            else:
                print(status)

            if launch_time_str:
                print_blue('Launched  : ', nl=False)
                print(f'{launch_time_str} ({launched_days_ago} ago)')    
            print_blue('ENI       : ', nl=False)
            print(eni_id)
            print_blue('Subnet    : ', nl=False)
            print(f'{subnet_id} ({subnet_name})')
            print_blue('VPC       : ', nl=False)
            print(f'{vpc_id} ({vpc_name})')

            print_blue('CIDR      : ', nl=False)
            print(cidr)
            print_blue('IPs       : ', nl=False)
            print(private_ips_str)
            if public_ips:
                print_blue('Public IPs: ', nl=False)
                print(public_ips_str)
            print_blue('AZ        : ', nl=False)
            print(az)
            print_blue('SGs       : ', nl=False)
            print(sgs_str)

            if len(all_enis) > 1:
                print('-'*20)
        elif output_type == 'quick':
            print(f'{service} | {name} | {eni_role_name} | {private_ips_str}')
        elif output_type == 'all':
            if first_run:
                first_run = False
                output_csv_writer.writerow(
                    ['Service', 'Name', 'Role Name','Launch Time','ENI ID', 'Subnet', 'CIDR', 'AZ', 'VPC', 'Security Groups', 'Status', 'Managed', 'IP'])

            output_csv_writer.writerow([service, name, eni_role_name, launch_time_str,eni_id, f'{subnet_id} ({subnet_name})', cidr, az, f'{vpc_id} ({vpc_name})', sgs_str, status, managed, private_ips_str])
            output_csv_file.flush()
            count += 1
            print(f'\rChecking IP {count}/{len(all_enis)}', end='')

    if output_type == 'all':
        output_csv_file.close()
        print()
        print_green(f'CSV written to: {output_file_name}')


# -----------------------------------------------
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print_red("\r  \nInterrupted by Ctrl+C\n")
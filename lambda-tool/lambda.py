#!/usr/bin/env python
import os
import re
import sys
import json
import boto3
import base64
import shutil
import click
import zipfile
import datetime
import requests
import tempfile
from time import sleep

# Click Functions


class AliasedGroup(click.Group):
    """Used as cls in Click Groups to allow short commands"""

    def get_command(self, ctx, cmd_name):
        rv = click.Group.get_command(self, ctx, cmd_name)
        if rv is not None:
            return rv
        matches = [
            x for x in self.list_commands(ctx)
            if x.startswith(cmd_name)
        ]
        if not matches:
            return None
        elif len(matches) == 1:
            return click.Group.get_command(self, ctx, matches[0])
        ctx.fail('Too many matches: %s' % ', '.join(sorted(matches)))


# Helper Functions

def ask(question):
    """Ask a yes/no question"""
    while True:
        reply = str(input(question+' (y/n): ')).lower().strip()
        try:
            if reply[0] == 'y':
                return True
            elif reply[0] == 'n':
                return False
        except IndexError:
            pass


def print_green(message, nl=True):
    click.echo(click.style(str(message), fg='bright_green'), nl=nl)


def print_blue(message, nl=True):
    click.echo(click.style(str(message), fg='bright_blue'), nl=nl)


def print_yellow(message, nl=True):
    click.echo(click.style(str(message), fg='bright_yellow'), nl=nl)


def print_red(message, nl=True):
    click.echo(click.style(str(message), fg='bright_red'), nl=nl)


def remove_prefix(text, prefix):
    if text.startswith(prefix):
        return text[len(prefix):]
    return text


def get_current_epoch():
    """Get current epoch time"""
    return int(datetime.datetime.now().strftime('%s'))*1000


# File Functions

def get_temp_file():
    return list(tempfile.mkstemp())[1]


def list_folder(dir_name):
    ''' Get dict of all files names and modified dates in a folder '''
    if not os.path.isdir(dir_name):
        if not os.path.exists(dir_name):
            print_red(f"Error: Folder {dir_name} doesn't exist")
        else:
            print_red(f"Error: Folder {dir_name} is not a folder")
        return {}

    cwd = os.getcwd()
    os.chdir(dir_name)
    result = {}
    for root, dirs, files in os.walk('.'):
        for file in files:
            root = re.sub(r'^.\/?(.*)$', r'\1', root)
            full_path = os.path.join(root, file)
            data = open(full_path,'rb').read()
            result[full_path] = data
    os.chdir(cwd)
    return result


def save_folder(dir_name, data):
    shutil.rmtree(dir_name)
    os.mkdir(dir_name)
    for file_name in data:
        full_path = f'{dir_name}/{file_name}'
        value = data[file_name]
        if not os.path.exists(os.path.dirname(full_path)):
            try:
                os.makedirs(os.path.dirname(full_path))
            except OSError as exc:  # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise
        if full_path.endswith('/'):
            try:
                os.mkdir(full_path)
            except FileExistsError:
                pass
        else:
            with open(full_path, 'wb') as f:
                f.write(value)


def zipdir(dir_name, zip_file_name):
    ''' Zip a folder to a file '''
    if not os.path.isdir(dir_name):
        if not os.path.exists(dir_name):
            print(f"Error: {dir_name} doesn't exist")
        else:
            print(f"Error: {dir_name} is not a folder")
        return False
    else:
        cwd = os.getcwd()
        ziph = zipfile.ZipFile(zip_file_name, 'w', zipfile.ZIP_DEFLATED)
        os.chdir(dir_name)
        for root, dirs, files in os.walk('.'):
            for file in files:
                root = remove_prefix(root, dir_name)
                ziph.write(os.path.join(root, file))
        ziph.close()
        os.chdir(cwd)
        return True


def extract_zip(input_zip):
    input_zip = zipfile.ZipFile(input_zip)
    return {name: input_zip.read(name) for name in input_zip.namelist()}


# Lambda related functions

def get_lambda_functions():
    client = boto3.client('lambda')
    finished = False
    token = ''
    all_functions = {}
    while not finished:
        if token:
            response = client.list_functions(MaxItems=10000, Marker=token)
        else:
            response = client.list_functions(MaxItems=10000)

        if 'NextMarker' in response:
            token = response['NextMarker']
        else:
            finished = True
        for func in response['Functions']:
            function_name = func['FunctionName']
            all_functions[function_name] = func
    return all_functions


def get_lambda_code(function_name):
    temp_downloaded_zip_file = list(tempfile.mkstemp())[1]
    client = boto3.client('lambda')
    try:
        response = client.get_function(FunctionName=function_name)
    except client.exceptions.ResourceNotFoundException:
        print_red(f'Error: Lambda Function not found: {function_name}\n')
        return {'error': 'not found'}

    code_link = response['Code']['Location']
    response = requests.get(code_link)
    data = response.content
    with open(temp_downloaded_zip_file, 'wb') as zfile:
        zfile.write(data)

    data = extract_zip(temp_downloaded_zip_file)
    os.remove(temp_downloaded_zip_file)
    return {'result': data}


def update_function_dir(function_name, dir_name):
    ''' Update Lambda Function Code from a folder'''
    result = False
    temp_zip_file_name = get_temp_file()
    if zipdir(dir_name, temp_zip_file_name):
        zip_data = open(temp_zip_file_name, 'rb').read()
        client = boto3.client('lambda')
        try:
            response = client.update_function_code(
                FunctionName=function_name,
                ZipFile=zip_data,
                Publish=True,
            )
        except client.exceptions.ResourceNotFoundException:
            print_red(f'Error: Lambda Function not found: {function_name}\n')
        else:
            if 'LastUpdateStatus' in response and response['LastUpdateStatus'] == 'Successful':
                result = True

        os.remove(temp_zip_file_name)

    return result


def create_lambda_function(function_name, dir_name, role_arn, runtime, handler, memory, timeout):
    temp_zip_file_name = get_temp_file()
    if zipdir(dir_name, temp_zip_file_name):
        zip_data = open(temp_zip_file_name, 'rb').read()
        client = boto3.client('lambda')
        finished = False
        while not finished:
            try:
                response = client.create_function(
                    FunctionName=function_name,
                    Runtime=runtime,
                    Role=role_arn,
                    Handler=handler,
                    Code={'ZipFile': zip_data},
                    Description='',
                    Timeout=timeout,
                    MemorySize=memory,
                    Publish=True,
                    PackageType='Zip'
                )
                return True
            except client.exceptions.ResourceNotFoundException:
                print_red(f'Error: Lambda Function not found: {function_name}\n')
                finished = True
            except client.exceptions.ClientError as err:
                err_code = err.response['Error']['Code']
                err_msg = err.response['Error']['Message']
                if 'The role defined for the function cannot be assumed by Lambda' in err_msg:
                    continue
                print_red(f'Error creating Lambda function - {err_msg}')
                finished = True

        os.remove(temp_zip_file_name)

    return False


def get_sample_code(runtime):
    if 'python' in runtime:
        file_name = 'lambda_function.py'
        handler = 'lambda_function.lambda_handler'
        code = '''import json

def lambda_handler(event, context):
    print(event)
    return {
        'statusCode': 200,
        'body': 'ok'
    }
'''
    elif 'nodejs' in runtime:
        file_name = 'index.js'
        handler = 'index.handler'
        code = '''exports.handler = async (event) => {
// TODO implement
const response = {
    statusCode: 200,
    body: JSON.stringify('ok'),
};
return response;
};
'''
    elif 'ruby' in runtime:
        file_name = 'lambda_function.rb'
        handler = 'lambda_function.lambda_handler'
        code = '''require 'json'

def lambda_handler(event:, context:)
# TODO implement
{ statusCode: 200, body: JSON.generate('ok') }
end
'''
    else:
        file_name = 'lambda_function.txt'
        handler = 'lambda_function.lambda_handler'
        code = ''
    return file_name, handler, code


# Cloudwatch functions

def get_events_from_cw(log_group_name, stream_name, start_time):
    """Get logs from Cloudwatch"""
    end_time = get_current_epoch() + 86400000
    client = boto3.client('logs')
    token = ''
    events = []
    finished = False
    while not finished:
        try:
            if token:
                response = client.get_log_events(
                    logGroupName=log_group_name,
                    logStreamName=stream_name,
                    startTime=start_time,
                    endTime=end_time,
                    startFromHead=True,
                    nextToken=token,
                )
            else:
                response = client.get_log_events(
                    logGroupName=log_group_name,
                    logStreamName=stream_name,
                    startTime=start_time,
                    startFromHead=True,
                    endTime=end_time,
                )
        except client.exceptions.ClientError as err:
            err_code = err.response['Error']['Code']
            if err_code == 'ResourceNotFoundException':
                return []
            else:
                print_red('Error {err_code}: '+str(err))

        if 'nextBackwardToken' in response and token != response['nextBackwardToken']:
            token = response['nextBackwardToken']
        else:
            finished = True
        if 'events' in response:
            events += response['events']

    return events


def get_streams(log_group_name):
    client = boto3.client('logs')
    try:
        response = client.describe_log_streams(
            logGroupName=log_group_name,
            orderBy='LastEventTime',
            descending=True,
            limit=50
        )
    except client.exceptions.ResourceNotFoundException:
        return {'error': f'Log Group {log_group_name} not found'}
    else:
        return response['logStreams']


def get_function_role(function_name):
    client = boto3.client('lambda')
    try:
        response = client.get_function(FunctionName=function_name)
        return response['Configuration']['Role']
    except client.exceptions.ResourceNotFoundException:
        print_red(f'Error: Lambda Function not found: {function_name}')
    return ''


def delete_function(function_name):
    client = boto3.client('lambda')
    try:
        response = client.delete_function(FunctionName=function_name)
        return True
    except client.exceptions.ResourceNotFoundException:
        print_red(f'Error: Lambda Function not found: {function_name}\n')
    return False


# IAM Functions

def get_account_id():
    try:
        client = boto3.client('sts')
        return client.get_caller_identity().get('Account')
    except client.exceptions.ClientError as err:
        if re.match(r'(InvalidClientTokenId|AuthFailure)', vars(err)['response']['Error']['Code']):
            print_red('Error: Missing or invalid keys\n')
        else:
            err_code = err.response['Error']['Code']
            print_red(f'Error getting account ID - {err_code}')
    return ''


def create_iam_policy(policy_name, policy_doc):
    client = boto3.client('iam')
    description = f'Basic policy for Lambda function'
    try:
        response = client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_doc),
            Description=description,
        )
        print_green(f'Policy {policy_name} created successfully')
        return response['Policy']['Arn']
    except client.exceptions.EntityAlreadyExistsException as err:
        print_yellow(f'policy {policy_name} already exists')
    except client.exceptions.ClientError as err:
        err_code = err.response['Error']['Code']
        print_red(f'Error creating IAM Policy {policy_name} - {err_code}')
    return ''


def attach_policy_to_role(role_name, policy_arn):
    """Attach IAM Policy to IAM Role"""
    client = boto3.client('iam')
    try:
        client.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn,
        )
        print_green('Success')
        return True
    except client.exceptions.ClientError as err:
        err_code = err.response['Error']['Code']
        print_red(f'Error creating IAM Policy {policy_arn} - {err_code}')

    return False


def create_role(role_name):
    """Create new IAM Role"""
    assume_role_policy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {
                    'Service': 'lambda.amazonaws.com',
                },
                'Action': 'sts:AssumeRole',
            },
        ],
    }
    try:
        client = boto3.client('iam')
        response = client.create_role(
            Path='/',
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy),
            Description='IAM Role',
            MaxSessionDuration=3600,
        )
        print_green(f'Role {role_name} created successfully')
        return response['Role']['Arn']
    except client.exceptions.EntityAlreadyExistsException:
        print_yellow(f'Role {role_name} already exists')
    except client.exceptions.ClientError as err:
        err_code = err.response['Error']['Code']
        print_red(f'Error creating IAM Policy {policy_name} - {err_code}')

    return ''


def get_role_policies(role_name):
    client = boto3.client('iam')
    response = client.list_attached_role_policies(RoleName=role_name)
    attached_policies = response['AttachedPolicies']
    policies_arn = {x['PolicyArn']: x['PolicyName'] for x in attached_policies}
    return policies_arn


def delete_iam_policy(policy_arn):
    client = boto3.client('iam')
    try:
        response = client.delete_policy(PolicyArn=policy_arn)
        return True
    except client.exceptions.ClientError as err:
        err_code = err.response['Error']['Code']
        print_red(f'Error: {err_code}')
        return False


def detach_role_policy(role_name, policy_arn):
    client = boto3.client('iam')
    try:
        response = client.detach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn,
        )
        return True
    except client.exceptions.ClientError as err:
        err_code = err.response['Error']['Code']
        print_red(f'Error: {err_code}')
        return False


def delete_iam_role(role_name):
    client = boto3.client('iam')
    try:
        response = client.delete_role(RoleName=role_name)
        return True
    except client.exceptions.ClientError as err:
        err_code = err.response['Error']['Code']
        print_red(f'Error: {err_code}')
        return False

# Click Commands


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(context_settings=CONTEXT_SETTINGS, cls=AliasedGroup)
def cli():
    pass


@cli.command()
@click.option('--function_name', '-f', required=True, help='Lambda Function Name')
@click.option('--interval', '-i', default=0, type=int, help='Interval between change checks')
def watch(function_name, interval):
    ''' Tail CW logs of Lambda Function '''
    saved_streams_list = {}
    first_run = True
    last_ingestion_time = 0
    cw_log_group_name = f'/aws/lambda/{function_name}'
    while True:
        streams = get_streams(cw_log_group_name)
        if 'error' in streams:
            print_red('Error: '+streams['error'])
            return
        for stream in streams:
            stream_name = stream['logStreamName']
            stream_last_event_time = stream['lastIngestionTime']
            stream_size = stream['storedBytes']
            if first_run and stream_last_event_time > last_ingestion_time:
                last_ingestion_time = stream_last_event_time

            if not stream_name in saved_streams_list and first_run:
                saved_streams_list[stream_name] = {
                    'last_event_time': stream_last_event_time, 'size': stream_size, 'events': []}
            elif (not first_run and not stream_name in saved_streams_list) or saved_streams_list[stream_name]['last_event_time'] != stream_last_event_time or saved_streams_list[stream_name]['size'] != stream_size:
                if not stream_name in saved_streams_list:
                    saved_streams_list[stream_name] = {'events': []}

                saved_streams_list[stream_name]['last_event_time'] = stream_last_event_time
                saved_streams_list[stream_name]['size'] = stream_size

                events = get_events_from_cw(
                    cw_log_group_name, stream_name, last_ingestion_time)
                for event in events:
                    if not event in saved_streams_list[stream_name]['events']:
                        msg = event['message']
                        ingestion_time = event['ingestionTime']
                        if ingestion_time > last_ingestion_time:
                            duration = billed_duration = max_mem_used = ''
                            if not re.match(r'^(START|END|REPORT) RequestId: ', msg):
                                print(msg, end='')
                            if re.match(r'^REPORT RequestId: .*Duration: (\S+ \S+).*Billed Duration: (\S+ \S+).*Max Memory Used: (\S+ \S+).*$', msg):
                                duration, billed_duration, max_mem_used = re.findall(
                                    r'^REPORT RequestId: .*Duration: (\S+ \S+).*Billed Duration: (\S+ \S+).*Max Memory Used: (\S+ \S+).*$', msg)[0]
                                print('-'*40)
                                print_blue('Duration        : ', nl=False)
                                print(duration)
                                print_blue('Billed Duration : ', nl=False)
                                print(billed_duration)
                                print_blue('Max Memory Used : ', nl=False)
                                print(max_mem_used)
                                print('-'*40)
                                print()

                        saved_streams_list[stream_name]['events'].append(event)
                        sys.stdout.flush()

        if first_run:
            print_green('Watching...')
            first_run = False
        if interval:
            sleep(interval)


@cli.command()
@click.option('--function_name', '-f', required=True, help='Lambda Function Name')
@click.option('dir_name', '--dir', '-d', required=True, help='Directory to sync')
@click.option('--interval', '-i', default=1, type=int, help='Interval between change checks')
@click.option('--one', '-o', is_flag=True, default=False, help="One time update")
def sync(function_name, dir_name, interval, one):
    """ Sync Lambda Function Code with local folder"""
    new_folder = False
    if not os.path.isdir(dir_name):
        if os.path.exists(dir_name):
            print_red(f'Error: {dir_name} is not a folder')
            return
        else:
            new_folder = True

    remote_code_raw = get_lambda_code(function_name)
    if 'error' in remote_code_raw:
        return
    remote_code = remote_code_raw['result']

    if new_folder:
        os.mkdir(dir_name)
        saved_data = {}
    else:
        saved_data = list_folder(dir_name)

    if saved_data == remote_code:
        print_green('Up to Date!')
    else:
        if new_folder:
            print_blue('Creating new folder: ', nl=False)
            print(dir_name)
        else:
            print_red('Local Code is different from Lambda code!')
        if new_folder or ask('Do you want to overwrite local folder with data FROM lambda?'):
            save_folder(dir_name, remote_code)
            saved_data = remote_code
        else:
            print('Updating Lambda Function...')
            result = update_function_dir(function_name, dir_name)
        if not one:
            print_green('Up to Date!')

    while not one:
        sleep(interval)
        temp_saved_data = list_folder(dir_name)
        if saved_data != temp_saved_data:
            saved_data = temp_saved_data
            print('Updating Lambda Function...', end='')
            sys.stdout.flush()
            result = update_function_dir(function_name, dir_name)
            if result:
                print_green('\n\nUp to Date!')
            else:
                print_red('\n\nFailed!')


@cli.command()
@click.option('--function_name', '-f', required='True', help='Lambda Function Name')
@click.option('--payload', '-p', type=click.File('r'), default='/dev/null', help='Payload File')
@click.option('--text', '-t', type=str, default='', help='Text to send as Payload')
def invoke(function_name, payload, text):
    """ Invoke Lambda Function """

    payload_data = payload.read()
    if not payload_data:
        payload_data = text

    if payload_data:
        try:
            json_test = json.loads(payload_data)
        except:
            print_red('Error: Payload is not in json format\n')
            return

    print_blue('Invoking Lambda... ', nl=False)
    client = boto3.client('lambda')
    try:
        response = client.invoke(
            FunctionName=function_name,
            InvocationType='RequestResponse',
            LogType='Tail',
            Payload=payload_data,
        )
    except client.exceptions.ResourceNotFoundException:
        print_red(f'Error: Lambda Function not found: {function_name}\n')
        return False

    status_code = response['ResponseMetadata']['HTTPStatusCode']

    if 'x-amz-function-error' in response['ResponseMetadata']['HTTPHeaders']:
        print_red('Error!')
        state = 'error'
    else:
        state = 'ok'
        print_green('Success!')
    print('-'*40)

    log_lines = base64.b64decode(response['LogResult']).decode().splitlines()
    duration = billed_duration = max_mem_used = ''
    output_lines = []
    for line in log_lines:
        if not re.match(r'^(START|END|REPORT) RequestId: ', line):
            output_lines.append(line)
        if re.match(r'^REPORT RequestId: .*Duration: (\S+ \S+).*Billed Duration: (\S+ \S+).*Max Memory Used: (\S+ \S+).*$', line):
            duration, billed_duration, max_mem_used = re.findall(
                r'^REPORT RequestId: .*Duration: (\S+ \S+).*Billed Duration: (\S+ \S+).*Max Memory Used: (\S+ \S+).*$', line)[0]
    output_payload = response['Payload'].read().decode()
    if output_payload and output_payload != 'null' and state != 'error':
        print_blue('Result:')
        print(output_payload)
        print('-'*40)
    print_blue('Log Output:')
    for line in output_lines:
        print(line)

    # Print summary
    print('-'*40)
    print()
    print_blue('Duration        : ', nl=False)
    print(duration)
    print_blue('Billed Duration : ', nl=False)
    print(billed_duration)
    print_blue('Max Memory Used : ', nl=False)
    print(max_mem_used)


@cli.command()
@click.option('--function_name', '-f', type=str, required=True, help='Lambda Function Name')
@click.option('dir_name', '--dir', '-d', type=str, help='Directory to sync')
@click.option('--runtime', type=str, required=False, default='python3.7', help='Directory to sync')
@click.option('--handler', type=str, required=False, default='', help='Handler Method to use')
@click.option('--timeout', type=int, required=False, default=60, help='Timeout in seconds. Max is 900')
@click.option('--memory', type=int, required=False, default=1024, help='Memory to use. between 128-10240')
@click.option('--quick', '-q', is_flag=True, default=False, help="Don't ask questions")
def create(function_name, dir_name, runtime, handler, timeout, memory, quick):
    ''' Create new Lambda Function '''

    # Check if lambda already exists
    all_functions = get_lambda_functions()
    if function_name in all_functions:
        print_red(f'Function {function_name} already exists\n')
        return

    file_name, temp_handler, code = get_sample_code(runtime)
    if not handler:
        handler = temp_handler

    if not dir_name:
        dir_name = f'lambda_{function_name}'
        if os.path.exists(dir_name):
            if not quick and not ask(f'Folder {dir_name} will be overwritten. Do you approve?'):
                return
            shutil.rmtree(dir_name)
        print_blue('Creating new folder: ', nl=False)
        os.mkdir(dir_name)

        with open(f'{dir_name}/{file_name}', 'w') as f:
            f.write(code)

        print(dir_name)
    elif not os.path.exists(dir_name):
        print_red(f"Error: Folder {dir_name} doesn't exist")
        return
    elif not os.path.isdir(dir_name):
        print_red(f"Error: {dir_name} is not a folder")
        return

    # Create IAM Policy for basic CW logs write access
    print_blue('Creating basic IAM Policy.. ', nl=False)
    cw_log_group_name = f'/aws/lambda/{function_name}'
    role_name = f'lambda_{function_name}-role'
    policy_name = f'lambda_{function_name}_basic_cw_policy'

    policy_doc = {
        'Version': '2012-10-17',
        'Statement': [{
            'Sid': 'WriteCWLogs',
            'Effect': 'Allow',
            'Action': [
                'logs:CreateLogGroup',
                'logs:CreateLogStream',
                'logs:PutLogEvents'
            ],
            'Resource': [
                f'arn:aws:logs:*:*:log-group:{cw_log_group_name}',
                f'arn:aws:logs:*:*:log-group:{cw_log_group_name}:*'
            ],
        }],
    }
    policy_arn = create_iam_policy(policy_name, policy_doc)
    account_id = ''
    if not policy_arn:
        account_id = get_account_id()
        policy_arn = f'arn:aws:iam::{account_id}:policy/{policy_name}'

    # Create IAM role for Lambda function
    print_blue('Creating IAM role.. ', nl=False)
    role_arn = create_role(role_name)
    if not role_arn:
        if not account_id:
            account_id = get_account_id()
        role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'

    # Attach basic policy to role
    print_blue('Attaching policy to role.. ', nl=False)
    attach_policy_to_role(role_name, policy_arn)

    print_blue('Creating Lambda function.. ', nl=False)
    if create_lambda_function(function_name, dir_name, role_arn, runtime, handler, memory, timeout):
        print_green('Success')


def update_function(function_name, attrs):
    try:
        client = boto3.client('lambda')
        print(attrs)
        response = client.update_function_configuration(**attrs)
        return True
    except client.exceptions.ClientError as err:
        err_msg = err.response['Error']['Message']
        print_red(f'Error: - {err_msg}')

    return False


@cli.command()
@click.option('--function_name', '-f', type=str, required=True, help='Lambda Function Name')
@click.option('--runtime', type=str, help='Directory to sync')
@click.option('--handler', type=str, help='Handler Method to use')
@click.option('--timeout', type=int, help='Timeout in seconds. Max is 900')
@click.option('--memory', type=int, help='Memory to use. between 128-10240')
def update(function_name, runtime, handler, timeout, memory):
    ''' Create new Lambda Function '''
    attrs = {}
    if runtime:
        attrs['Runtime'] = runtime
    if handler:
        attrs['Handler'] = handler
    if timeout:
        attrs['Timeout'] = timeout
    if memory:
        attrs['MemorySize'] = memory
    if not attrs:
        print_red('No option was chosen')
        return
    attrs['FunctionName'] = function_name

    print_blue('Updating Lambda function.. ', nl=False)
    if update_function(function_name, attrs):
        print('OK')


def delete_log_group(log_group_name):
    client = boto3.client('logs')
    try:
        response = client.delete_log_group(logGroupName=log_group_name)
        return True
    except client.exceptions.ClientError as err:
        err_msg = err.response['Error']['Message']
        print_red(f'Error: - {err_msg}')
    return False


@cli.command()
@click.option('--function_name', '-f', type=str, required=True, help='Lambda Function Name')
@click.option('--quick', '-q', is_flag=True, default=False, help="Don't ask questions")
def delete(function_name, quick):
    ''' Delete a Lambda function and attached resources '''

    print_blue('Check if function exist... ', nl=False)
    function_exists = role_arn = get_function_role(function_name)

    cw_log_group_name = f'/aws/lambda/{function_name}'
    role_name = re.sub(r'^.*\/([^\/]+)$', r'\1', role_arn)
    # Delete Lambda Function
    if role_arn:

        print_green('OK')
        policies = get_role_policies(role_name)
    else:
        account_id = get_account_id()
        role_name = f'lambda_{function_name}-role'
        policy_name = f'lambda_{function_name}_basic_cw_policy'
        policies = {f'arn:aws:iam::{account_id}:policy/{policy_name}': policy_name}
        role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'

    print_yellow('The following resources will be deleted:')
    print(f'Role: {role_name}')
    print(f'Log Group: {cw_log_group_name}')
    for policy_arn in policies:
        policy_name = policies[policy_arn]
        print(f'Policy: {policy_name}')
    print()
    if not quick and not ask('Do you approve?'):
        return

    if function_exists:
        print_blue('Deleting Lambda function.. ', nl=False)
        if delete_function(function_name):
            print_green('Success')

    for policy_arn in policies:
        policy_name = policies[policy_arn]
        print_blue(f'Detaching policy {policy_name} from role {role_name}... ', nl=False)
        if detach_role_policy(role_name, policy_arn):
            print_green('OK')

        print_blue(f'Deleting policy {policy_name}... ', nl=False)
        if delete_iam_policy(policy_arn):
            print_green('OK')

    print_blue(f'Deleting IAM Role {role_name}... ', nl=False)
    if delete_iam_role(role_name):
        print_green('OK')

    print_blue(f'Deleting Log Group {cw_log_group_name}... ', nl=False)
    if delete_log_group(cw_log_group_name):
        print_green('OK')


@cli.command(name='list')
def list_functions():
    ''' List all Lambda functions in account '''
    all_functions = get_lambda_functions()
    if not all_functions:
        print_red('No Functions')
        return
    print_green(f'{len(all_functions)} Functions:')
    print_functions = []
    for function_name in all_functions:
        runtime = all_functions[function_name]['Runtime']
        mem_size = all_functions[function_name]['MemorySize']
        handler = all_functions[function_name]['Handler']
        timeout = all_functions[function_name]['Timeout']
        code_size = all_functions[function_name]['CodeSize']
        print_functions.append(
            [function_name, runtime, mem_size, timeout, code_size, handler])

    print_functions.insert(
        0, ['Function Name', 'Runtime', 'Memory', 'Timeout', 'Code Size', 'Handler'])

    max_lens = []
    for i in range(len(print_functions[0])):
        maxi = max([len(str(x[i])) for x in print_functions])
        max_lens.append(maxi)

    first = True
    for func in print_functions:
        index = 0
        if first:
            first = False
            for obj in func:
                if index < len(func)-1:
                    print_blue(f'%-*s | ' % (max_lens[index], func[index]), nl=False)
                else:
                    print_blue(func[index])
                index += 1
        else:
            for obj in func:
                if index < len(func)-1:
                    print(f'%-*s | ' % (max_lens[index], func[index]), end='')
                else:
                    print(func[index])
                index += 1


def main():
    cli()


if __name__ == '__main__':
    main()

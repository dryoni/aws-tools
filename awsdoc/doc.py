#!/usr/bin/env python
import botocore
import boto3
import re
import sys
import webbrowser


# Boto related lists

MODIFIED_BOTO3_CLASS_NAMES = {'configservice': 'config',
                              'opsworks-cm': 'opsworkscm',
                              'deploy': 'codedeploy',
                              's3api': 's3'
                              }

BOTO3_ONLY_METHODS = [	'can_paginate',
                       'generate_presigned_url',
                       'get_paginator',
                       'get_waiter'
                       ]

# Helper functions

def print_red(message):
    print("\033[1;31;40m%s\033[1;37;40m" % message)


def get_client_class_name(service_name):
    try:
        return boto3.client(service_name).__class__.__name__
    except:
        return ''


def get_modified_service_name(value):
    for key in MODIFIED_BOTO3_CLASS_NAMES:
        if MODIFIED_BOTO3_CLASS_NAMES[key] == value:
            return key
    return value


# Main

def main():
    args = sys.argv
    args.pop(0)
    if args and args[0] == 'aws':
        args.pop(0)

    all_services = botocore.session.get_session().get_available_services() + \
        ['configure']

    # Print all AWS services
    if not args:
        for service in all_services:
            print('aws %s' % service)
        return

    service_name = args[0]
    mod_service_name = service_name
    if service_name in MODIFIED_BOTO3_CLASS_NAMES:
        mod_service_name = MODIFIED_BOTO3_CLASS_NAMES[service_name]

    # Open AWS Docs for specific service and action
    action_name = ''
    if len(args) > 1:
        action_name = args[1]
        class_name = get_client_class_name(mod_service_name)
        if not class_name:
            print_red('No such service: %s' % service_name)
            return
        mod_action_name = re.sub('-', '_', action_name)
        if mod_service_name == 'configure':
            boto3_configure_url = 'https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html'
            cli_configure_url = 'https://docs.aws.amazon.com/cli/latest/reference/configure/'
        else:
            boto3_doc_url = 'https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/%s.html#%s.Client.%s' % (
                mod_service_name, class_name, mod_action_name)
            cli_doc_url = 'https://docs.aws.amazon.com/cli/latest/reference/%s/%s.html' % (
                service_name, action_name)

        webbrowser.open_new(boto3_doc_url)
        webbrowser.open_new(cli_doc_url)
        return

    # Find matching services
    found_services = []
    if mod_service_name in all_services:
        found_services = [mod_service_name]
    else:
        for service in all_services:
            if re.match(mod_service_name, service):
                found_services.append(service)

    if not found_services:
        print_red("Error: Service %s doesn't exist\n" % mod_service_name)
        return

    # Multiple matching services
    if len(found_services) > 1:
        for service in found_services:
            print('aws %s' % service)
        return

    mod_service_name = service_name = found_services[0]
    if mod_service_name in MODIFIED_BOTO3_CLASS_NAMES:
        mod_service_name = MODIFIED_BOTO3_CLASS_NAMES[mod_service_name]

    try:
        client = boto3.client(mod_service_name)
    except Exception as e:
        print_red('Error creating client: %s' % str(e))
        return

    # Find available actions
    available_methods = []
    for method in dir(client):
        if type(getattr(client, method)).__name__ == 'method' and not re.match(r'^_.*$', method) and not method in BOTO3_ONLY_METHODS:
            available_methods.append(method)

    # Print available actions
    rev_service_name = get_modified_service_name(service_name)
    for method in available_methods:
        method = re.sub('_', '-', method)
        print('aws %s %s' % (rev_service_name, method))


# -----------------------------------------------
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print_red("\r  \nInterrupted by Ctrl+C\n")

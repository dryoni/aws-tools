#!/usr/bin/env python3
import sys
import os
import socket
import threading
import datetime
import argparse
import re
import json
import dns.resolver
from time import sleep
from subprocess import call
from getpass import getuser
import boto3

# ==========================
#  Helper Functions
# ==========================

# Get a list of maximum string lengths from each column in a 2d list
def getMax(table):
	saved_max=[0]*len(table[0])
	for row in table:
		for i in range(0,len(row)):
			obj=row[i]
			if type(obj).__name__=='list':
				try:
					obj=', '.join(obj)
				except:
					obj=json.dumps(obj)
			obj_len=len(obj)
			if obj_len>saved_max[i]:
				saved_max[i]=obj_len
	return saved_max

# Get number of seconds from a start time to now
def diff_seconds(start_time):
  now = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).astimezone(tz=None)
  return (now-start_time).total_seconds()

# Ask a yes/no question
def ask(question):
  while True:
    reply = str(input(question+' (y/n): ')).lower().strip()
    try:
      if reply[0] == 'y':
        return True
      elif reply[0] == 'n':
        return False    
    except:
      pass


# Print in colors
def printGreen(message,new_line=True):
  if new_line:
    print("\033[1;32;40m%s\033[0;37;40m"%message)
  else:
    print("\033[1;32;40m%s\033[0;37;40m"%message,end='')

def printYellow(message,new_line=True):
  if new_line:
    print("\033[1;33;40m%s\033[0;37;40m"%message)
  else:
    print("\033[1;33;40m%s\033[0;37;40m"%message,end='')

def printBlue(message,new_line=True):
  if new_line:
    print("\033[1;34;40m%s\033[0;37;40m"%message)
  else:
    print("\033[1;34;40m%s\033[0;37;40m"%message,end='')

def printRed(message,new_line=True):
  if new_line:
    print("\033[1;31;40m%s\033[0;37;40m"%message)
  else:
    print("\033[1;31;40m%s\033[0;37;40m"%message,end='')

# convert set to list
def set_to_list(input_set):
	output_list=[]
	for key in input_set:
		output_list.append([key,input_set[key]])
	return output_list

# ==========================
#  Network Functions
# ==========================

# Get your external IP address
def getExternalIP():
	my_resolver = dns.resolver.Resolver()
	my_resolver.nameservers = ['8.8.8.8']
	ip=my_resolver.query("o-o.myaddr.l.google.com","TXT").response.answer[0][-1].strings[0].decode('utf8')
	if re.match(r'^.* ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\/32$',ip):
		ip=re.sub(r'^.* ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\/32$',r'\1',ip)
	else:
		ip=''
	return ip

# check tcp connectivity to IP and port
def check_con(address, port):
	# Create a TCP socket
	s = socket.socket()
	s.settimeout(3)
	try:
		s.connect((address, port))
		return True
	except socket.error as e:
		return False

# ==========================
#  AWS Functions
# ==========================

def process_boto3_client_error(error):
	try:
		if re.match(r'(AccessDenied|Unauthorized)',vars(error)['response']['Error']['Code']):
			action=vars(error)['operation_name']
			printRed("Error: No permissions for action %s. Please contact admin\n"%action)
		elif re.match(r'(InvalidClientTokenId|AuthFailure)',vars(error)['response']['Error']['Code']):
			printRed('Error: Missing or invalid keys\n')
		else:
			print("other error: ", vars(error))
	except Exception as e:
		printRed('Unknown error: ',error)
	sys.exit(0)

# Returns an array with information about all ec2 instances - Instance ID, Instance Name, Public IP, State, Attached Security Groups
def list_instances():
	
	ec2_list=[]
	client = boto3.client('ec2')
	token=""
	finished=False
	# Get raw data about all EC2 instances
	while not finished:
		try:
			if token:
				response = client.describe_instances(MaxResults=100, NextToken=token)
			else:
				response = client.describe_instances(MaxResults=100)
		except client.exceptions.ClientError as e:
			process_boto3_client_error(e)

		ec2_list+=response['Reservations']
		if 'NextToken' in response:
			token=response['NextToken']
		else:
			token=''
			finished=True

	# Loop through all instances
	instances=[]
	for reservation in ec2_list:
		for instance in reservation['Instances']:
			instanceID=instance['InstanceId']
			instanceState=instance['State']['Name']

			# Get Name Tag
			try:
				tags=instance['Tags']
			except:
				tags=[]
			instanceName=''
			for tag in tags:
				if tag['Key']=='Name':
					instanceName=tag['Value']

			# Get network interfaces info
			publicIPs=[]
			securityGroups={}
			ipStr=''
			for nic in instance['NetworkInterfaces']:
				for privateNic in nic['PrivateIpAddresses']:
					try:
						publicIPs.append(privateNic['Association']['PublicIp'])
					except:
						pass
				# Get Security Groups
				for sg in nic['Groups']:
					securityGroups.update({sg['GroupId']:sg['GroupName']})
			if not re.match(r'^term',instanceState):
				securityGroups=set_to_list(securityGroups)

				instances.append([instanceID, instanceName, publicIPs,instanceState,securityGroups])

	# Sort instances array by instance name
	instances.sort(key=lambda x: x[1].lower())
	return instances

# get own AWS username
def get_current_identity():
	try:
		client=boto3.client('sts')
		arn=client.get_caller_identity().get('Arn')
		username=re.sub(r'^.*\/([^\/]+)$',r'\1',arn)
		return username
	except client.exceptions.ClientError as e:
		return boto_client_exception(e)
	return ''

# runs an action on a security group - add rule / remove rule / change description
def sgRuleAction(function_name,sg_id,ip,protocol,port,description):
	if protocol=='ANY':
		perm=[
	        {
	            'IpProtocol': '-1',
	            'IpRanges': [
	                {
	                    'CidrIp': ip+'/32',
	                    'Description': description
	                },
	            ]
	        },
	    ]
	else:
		perm=[
	        {
	            'FromPort': port,
	            'ToPort': port,
	            'IpProtocol': protocol,
	            'IpRanges': [
	                {
	                    'CidrIp': ip+'/32',
	                    'Description': description
	                },
	            ]
	        },
	    ]
	try:
		client = boto3.client('ec2')
		response = getattr(client, function_name)(GroupId=sg_id,IpPermissions=perm)
		return response
	except client.exceptions.ClientError as e:
			process_boto3_client_error(e)
	except:
		return ''

# Get current state of an EC2 instance
def get_instance_state(instance_id):
	try:
		client = boto3.client('ec2')
		response = client.describe_instances(InstanceIds=[instance_id])
		return response['Reservations'][0]['Instances'][0]['State']['Name']
	except:
		return ''

# Start a stopped EC2 instance
def start_instance(instance_id):
	try:
		client = boto3.client('ec2')
		response = client.start_instances(InstanceIds=[instance_id])
		return True
	except client.exceptions.ClientError as e:
			process_boto3_client_error(e)
	except:
		return False

# Get public IPs of an EC2 instance
def get_public_ips(instance_id):
	try:
		client = boto3.client('ec2')
		response = client.describe_instances(InstanceIds=[instance_id])
	except:
		return []
	instance=response['Reservations'][0]['Instances'][0]
	instanceState=instance['State']['Name']
	# Get network interfaces info
	publicIPs=[]
	for nic in instance['NetworkInterfaces']:
		for privateNic in nic['PrivateIpAddresses']:
			try:
				publicIPs.append(privateNic['Association']['PublicIp'])
			except:
				pass

	return publicIPs

# Get info about all rules of a Security Group applied by this tool - username (from description), ip, protocol, port
def getInstanceRules(sg_id):
	rules=[]
	try:
		client = boto3.client('ec2')
		response = client.describe_security_groups(GroupIds=[sg_id])
		sg_perm=response['SecurityGroups'][0]['IpPermissions']
	except client.exceptions.ClientError as e:
		process_boto3_client_error(e)
	except:
		return []

	for rule in sg_perm:
		rule_protocol=rule['IpProtocol']
		if rule_protocol=='-1':
			rule_protocol='ANY'
		non_port_protocol=False
		if rule_protocol in ['tcp','udp']:
			rule_from_port=rule['FromPort']
			rule_to_port=rule['ToPort']
		else:
			non_port_protocol=True
			rule_to_port=-1
			rule_from_port=-1

		if non_port_protocol or rule_from_port==rule_to_port:
			for ip_range in rule['IpRanges']:
				rule_ip=ip_range['CidrIp']
				try:
					rule_description=ip_range['Description']
				except:
					rule_description=''

				if re.match(r'^.*\/32$',rule_ip) and re.match(r'^(.*) User Access$',rule_description):
					rule_ip=re.sub(r'^(.*)\/32$',r'\1',rule_ip)
					username=re.sub(r'^(.*) User Access$',r'\1',rule_description)
					rules.append([username,rule_ip,rule_protocol,rule_to_port])
	return rules

# ==========================
#  Main
# ==========================

def main():
	prog_name=os.path.splitext(os.path.basename(sys.argv[0]))[0]
	# Argument parser info
	prog_description="""This tool can be used to grant access to public instances on AWS for your external IP address, or to quicly access instances via SSH.
SSH Access Sequence:
  - The script starts the instance in case it's stopped
  - Adds a rule to the instance's Security Group to allow your External IP address access via port 22 (or other specified port) 
  - If -d argument is used the rule is removed a few seconds after initial SSH connection - Safer than VPN"""

	usage_text="""%s [INSTANCE_PARTIAL_DATA] [PROTOCOL] [PORT] [--revoke]
       %s [--ssh|-s] [user@INSTANCE_PARTIAL_DATA] [-p [SSH_PORT]] [-i [SSH_KEY]] [-u [SSH_USER]] [-d]
       %s [--list|-l]
       %s [INSTANCE_PARTIAL_DATA] [--list|-l]"""
	usage_text=usage_text%(tuple({prog_name})*len(re.findall('%s',usage_text)))
	
	# Get argmuents	
	parser = argparse.ArgumentParser()
	parser = argparse.ArgumentParser(description=prog_description, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.usage=usage_text

	parser.add_argument('instance', metavar='INSTANCE_PARTIAL_DATA', help='Instance ID / Public IP / Name / State', default='',nargs='?')
	parser.add_argument('protocol', metavar='PROTOCOL', help='tcp/udp/any', default='',nargs='?')
	parser.add_argument('port', metavar='PORT', help='Between 1-65535. not required with ANY protocol', default='',nargs='?')
	parser.add_argument('--revoke','-r', help="Revoke access", default=False, action='store_true' )
	parser.add_argument('--list','-l', help="List all EC2 Instances, or show access granted to an instance", default=False, action='store_true' )
	parser.add_argument('--ssh','-s', help="SSH to EC2 Instance", default=False, action='store_true' )
	parser.add_argument('-p', metavar='SSH_PORT', help='SSH Port number. Default is 22', default='22',nargs='?')
	parser.add_argument('-i', metavar='SSH_KEY', help='Path of the private key. Default is ~/.ssh/id_rsa', default='~/.ssh/id_rsa',nargs='?')
	parser.add_argument('-u', metavar='SSH_USER', help='SSH User to use. default is your OS username', default=getuser(),nargs='?')
	parser.add_argument('-d', help="delete rule a few seconds after connecting via SSH. Very useful in public wifi", default=False, action='store_true')
	args = parser.parse_args()

	findTerm=args.instance
	port=args.port
	revoke=args.revoke
	protocol=args.protocol.lower()
	ssh_port=int(args.p)
	ssh_key_path=os.path.expanduser((args.i))
	delete_rule=args.d
	
	# input validation
	if args.ssh:
		if not findTerm:
			printRed('Error: Instance partial data must be specified\n')
			parser.print_help()
			return
		if not os.path.isfile(ssh_key_path):
			printRed("Error: File %s doesn't exist\n"%ssh_key_path)
			return
		if re.match(r'^(.+)@(.+)$',findTerm):
			[ssh_user,findTerm]=re.findall(r'^(.+)@(.+)$',findTerm)[0]
		else:
			ssh_user=args.u
	elif not args.list:
		if not protocol:
			parser.print_help()
			return
		elif not re.match(r'^(tcp|udp|any|all)$',protocol):
			printRed('Error: only tcp,udp, and all are allowed as protocols\n')
			return
		# change protocol to -1 if any/all
		if re.match(r'^(any|all)$',protocol):
				protocol="ANY"
				port=-1
		elif not port:
			printRed('Error: Port must be specified for protocol %s\n'%protocol)
			return
		elif re.match(r'[^0-9]',port):
				printRed('Error: %s is not a valid port number\n'%port)
				return
		elif not 1 <= int(port) <= 65535:
			printRed('Error: port must be between 1-65535\n')
			return

		port=int(port)

	instances=list_instances()

	if not instances:
		printRed('No instances found in this region\n')
		return
	[maxInstanceID,maxInstanceName,maxIpStr,null,null]=getMax(instances)

	# Print out everything
	if args.list and not findTerm:
		printGreen("\nAvailable instances: ")
		print("========================================================")
		for [instanceID, instanceName, publicIPs,instanceState,securityGroups] in instances:
			ipStr=', '.join(publicIPs)
			if not ipStr:
				ipStr='No Public IP'
			if instanceState=='running' and not ipStr:
				printRed("%-*s | %-*s | %-*s | %s"%(maxInstanceID,instanceID,maxInstanceName,instanceName,maxIpStr,ipStr, instanceState))
			else:
				print("%-*s | %-*s | %-*s | %s"%(maxInstanceID,instanceID,maxInstanceName,instanceName,maxIpStr,ipStr, instanceState))
		print("========================================================\n")
	else:
		# Get all instances matching the instance partial data
		matchingInstances=[]
		for [instanceID, instanceName, publicIPs,instanceState,securityGroups] in instances:
			matchInfo=False
			ipStr=', '.join(publicIPs)
			for info in [instanceID, instanceName, ipStr,instanceState]:
				if re.match(r'^.*%s.*$'%findTerm,info,re.IGNORECASE):
					matchInfo=True
			if matchInfo:
				matchingInstances.append([instanceID, instanceName, publicIPs,instanceState,securityGroups])

		# Multiple instance found
		if len(matchingInstances)>1:
			print('Multiple Instances found:')
			count=0
			[maxInstanceID,maxInstanceName,maxIpStr,null,null]=getMax(matchingInstances)
			for [instanceID, instanceName, publicIPs,instanceState,securityGroups] in matchingInstances:
				count+=1
				ipStr=', '.join(publicIPs)
				if not ipStr:
					ipStr='No Public IP'
				if instanceState=='running' and not ipStr:	
					printRed("\t%2d.  %-*s | %-*s | %-*s | %s"%(count,maxInstanceID,instanceID,maxInstanceName,instanceName,maxIpStr,ipStr, instanceState))
				else:
					print("\t%2d.  %-*s | %-*s | %-*s | %s"%(count,maxInstanceID,instanceID,maxInstanceName,instanceName,maxIpStr,ipStr, instanceState))
			print()
			chosen=""
			while chosen=="":
				option=input("Choose Instance: ")
				if re.match(r"^[0-9]+$",option):
					intOption=int(option)
					if intOption>0 and intOption<=len(matchingInstances):
						chosen=intOption
			print()
		elif len(matchingInstances)==0:
			printRed("No instances found\n")
			return
		else:
			intOption=1
		[instanceID, instanceName, publicIPs,instanceState,securityGroups]=matchingInstances[intOption-1]

		if args.list:
			printBlue("Showing access to instance %s (%s):"%(instanceID,instanceName))
			for sg in securityGroups:
				sg_id=sg[0]
				acc_details=getInstanceRules(sg_id)
				if not acc_details:
					printRed('No rules found\n')
				else:
					for [rule_user,rule_ip,rule_protocol,rule_port] in acc_details:
						if rule_protocol=='ANY':
							print("\tUser %s | IP %s \tANY"%(rule_user,rule_ip))
						else:
							print("\tUser %s | IP %s \t%s %s"%(rule_user,rule_ip,rule_protocol.upper(),rule_port))
			print()
			return
		
		current_ip=getExternalIP()
		username=get_current_identity()
		ipStr=', '.join(publicIPs)
		if not ipStr:
			ipStr='No Public IP'
		
		printBlue("Instance    ",new_line=False)
		print(": %s (%s)"%(instanceID,instanceName))
		printBlue("Instance IP ",new_line=False)
		print(": %s"%ipStr)
		printBlue("AWS User    ",new_line=False)
		print(": %s"%(username))
		printBlue("User IP     ",new_line=False)
		print(": %s"%current_ip)
		print()

		ip_success=''
		if args.ssh:
			instance_launched=False
			if not publicIPs:
				if instanceState=='running':
					printRed('Error: Instance is not public\n')
					return
				else:
					printYellow('Instance is not running, trying to start it... ',new_line=False)
					if not start_instance(instanceID):
						printRed("Coudln't start instance\n")
						return
					else:
						instance_launched=True
						printGreen('Started...')
					instance_state=''
					start_time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).astimezone(tz=None)
					while instance_state!='running':
						print("  Waiting for Instance to be in running state: %.0d seconds\r"%diff_seconds(start_time),end='')
						instance_state=get_instance_state(instanceID)
						if instance_state!='running':
							sleep(1)
					print("Waiting for Instance to be in running state: %.0d seconds   "%diff_seconds(start_time))
					printGreen('Instance is running...')
					publicIPs=get_public_ips(instanceID)
			
			if not publicIPs:
				printRed('No public IPs\n')
				return
			elif not instance_launched:
				for ip in publicIPs:
					if check_con(ip,ssh_port):
						ip_success=ip
						con_success=True
						break

			revoke=False
			protocol='tcp'
			port=ssh_port

		if len(securityGroups)>1:
			print('Multiple Security Groups found:')
			count=0
			for [sg_id,sg_name] in securityGroups:
				count+=1
				print("\t%2d.  %s\t%s"%(count,sg_id,sg_name))
			print()
			chosen=""
			while chosen=="":
				option=input("Choose Instance: ")
				if re.match(r"^[0-9]+$",option):
					intOption=int(option)
					if intOption>0 and intOption<=len(securityGroups):
						chosen=intOption
		else:
			intOption=1
		
		[sg_id,sg_name]=securityGroups[intOption-1]

		description='%s User Access'%(username)

		if not ip_success:
			
			found_protocol=False
			found_port=False
			found_ip=False
			found_description=False
			found_exact_rule=False

			acc_details=getInstanceRules(sg_id)
			saved_rule_ip=''
			saved_rule_user=''
			for [rule_user,rule_ip,rule_protocol,rule_port] in acc_details:
				if protocol==rule_protocol:
					found_protocol=True
					if not rule_protocol in ['tcp','udp'] or (rule_protocol in ['tcp','udp'] and rule_port==port):
						found_port=True
						exact_rule=False
						if rule_ip==current_ip:
							found_ip=True
							exact_rule=True
						else:
							saved_rule_ip=rule_ip
							saved_rule_user=rule_user

						if rule_user==username:
							found_description=True
							if exact_rule==True:
								found_exact_rule=True
						
			description='%s User Access'%(username)
			rule_description='%s User Access'%(saved_rule_ip)
			if found_protocol and found_port:
				if found_ip:
					if revoke:
						if found_description:
							printYellow('Removing access... ',new_line=False)
							if sgRuleAction('revoke_security_group_ingress',sg_id,current_ip,protocol,port,description):
								printGreen("Succesfully removed rule")
							else:
								printRed("Error removing rule from SG: %s (%s)"%(sg_id,sg_name))
								return
						else:
							printRed("Access wasn't found\n")
							return

					else:
						if found_description:
							if not args.ssh:
								printGreen("Access already enabled")
						else:
							printYellow("changing description... ",new_line=False)
							if sgRuleAction('update_security_group_rule_descriptions_ingress',sg_id,current_ip,protocol,port,description):
								printGreen("Succesfully updated description\n")
							else:
								printRed("Error updating description for SG: %s (%s)"%(sg_id,sg_name))
								return
				elif not revoke:
					if found_description and not found_exact_rule:
						printYellow("removing old rule... ",new_line=False)
						saved_rule_description='%s User Access'%saved_rule_user
						if sgRuleAction('revoke_security_group_ingress',sg_id,saved_rule_ip,protocol,port,saved_rule_description):					
							printGreen("Succesfully removed old rule")
						else:
							printRed("Error removing old rule from SG: %s (%s)"%(sg_id,sg_name))
							return

					printYellow("adding new rule... ",new_line=False)
					if sgRuleAction('authorize_security_group_ingress',sg_id,current_ip,protocol,port,description):					
						printGreen("Succesfully added rule")
					else:
						printRed("Error adding rule to SG: %s (%s)\n"%(sg_id,sg_name))
						return
				else:
					printRed("Access wasn't found\n")
					return
			else:
				if revoke:
					printRed("Access wasn't found\n")
					return
				else:
					printYellow("adding new rule... ",new_line=False)
					if sgRuleAction('authorize_security_group_ingress',sg_id,current_ip,protocol,port,description):					
						printGreen("Succesfully added rule")
					else:
						printRed("Error adding rule to SG: %s (%s)\n"%(sg_id,sg_name))
						return
		if args.ssh:
			if not ip_success:
				if instance_launched:
					end_time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).astimezone(tz=None)+datetime.timedelta(minutes=1)
					start_time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).astimezone(tz=None)
					ssh_running=False
					while not ssh_running and diff_seconds(end_time)<0:
						print("  Waiting for SSH Service to be active: %.0d seconds\r"%diff_seconds(start_time),end='')
						for ip in publicIPs:
							if check_con(ip,ssh_port):
								ip_success=ip
								ssh_running=True
								break

						if not ip_success:
							sleep(1)
					print("Waiting for SSH Service to be active: %.0d seconds   "%diff_seconds(start_time))
					
						
					if not ssh_running:
						printRed('SSH service is not running, or other problem with connectivity')
						if sgRuleAction('revoke_security_group_ingress',sg_id,current_ip,protocol,ssh_port,description):
							printGreen('Access revoked to Instance\n')
						else:
							printRed('Error revoking access to instance\n')
						return
				else:
					for ip in publicIPs:
						if check_con(ip,ssh_port):
							ip_success=ip
							con_success=True
							break
			if ip_success:
				if delete_rule:
					def worker():
						sleep(4)
						sgRuleAction('revoke_security_group_ingress',sg_id,current_ip,protocol,ssh_port,description)
						return
					printYellow("Safe mode, Access will be revoked in a few seconds...")
					t = threading.Thread(target=worker)
					t.daemon = True
					t.start()

				print('='*40)
				print()
				if instance_launched:
					call(['ssh','-o','StrictHostKeyChecking=no','-i',ssh_key_path,'%s@%s'%(ssh_user,ip_success)])
				else:
					call(['ssh','-i',ssh_key_path,'%s@%s'%(ssh_user,ip_success)])

				if delete_rule:
					if t.is_alive():
						sgRuleAction('revoke_security_group_ingress',sg_id,current_ip,protocol,ssh_port,description)

				return
			else:
				ipStr=', '.join(publicIPs)
				printRed("\nNo connectivity to %s:%s"%(ipStr,ssh_port))
		else:
			print()

# ======================================================
if __name__ == '__main__':
  try:
    main()
  except KeyboardInterrupt:
    printRed("\r  \nInterrupted by Ctrl+C - Avoid doing this! \n")
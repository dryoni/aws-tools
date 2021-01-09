#!/usr/bin/env python3
import os
import boto3
import sys
import argparse
import datetime
from configparser import ConfigParser
from shutil import copyfile
from time import sleep


# ==========================
#  Helper Functions
# ==========================

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


# ==========================
# Credentials file Functions
# ==========================

def get_current_access_keys(credentials_file_path,profile):
  credentials_data=get_credentials_data(credentials_file_path)
  try:
    profile=credentials_data[profile]
  except KeyError:
    printRed("Error: No such profile in credentials file\n")
    print_profiles(credentials_file_path)
    return False
  except:
    return False
  try:
    current_key_id=profile['aws_access_key_id']
  except KeyError:
    printRed("Error: aws_access_key_id doesn't exist in profile %s\n"%profile)
    return False
  try:
    current_key_secret=profile['aws_secret_access_key']
  except KeyError:
    printRed("Error: aws_secret_access_key doesn't exist in profile %s\n"%profile)
    return False
  return [current_key_id,current_key_secret]

def backup_credentials_file(credentials_file_path):
  copyfile(credentials_file_path, credentials_file_path+'.bkp')
  printYellow("Created backup of credentials file : %s"%credentials_file_path+'.bkp')

def get_credentials_data(credentials_file_path):
  if os.path.isfile(credentials_file_path):
    aws_credentials = ConfigParser()
    try:
      if not aws_credentials.read(credentials_file_path):
        printRed("Error reading credentials file: %s\n"%credentials_file_path)
        return False
      return aws_credentials
    except:
      printRed('Error: Config File is not in correct format\n')
      return False
  else:
    printRed("File %s doesn't exist\n"%credentials_file_path)
    return False

def update_new_access_key(credentials_file_path,profile,access_key_id,access_key_secret):
  try:
    credentials_data=get_credentials_data(credentials_file_path)
    credentials_data.set(profile, 'aws_access_key_id', access_key_id)
    credentials_data.set(profile, 'aws_secret_access_key', access_key_secret)
    with open(credentials_file_path, 'w') as aws_credentials_file:
      credentials_data.write(aws_credentials_file)
    printGreen('New access key upadted in credentials file')
    return True
  except:
    return False


# ==========================
#  AWS Functions
# ==========================

def diff_seconds(start_time):
  now = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).astimezone(tz=None)
  return (now-start_time).total_seconds()

def test_access_keys(access_key_id,access_key_secret):
  start_time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).astimezone(tz=None)
  client = boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=access_key_secret)
  while True:
    try:
      result = client.list_access_keys(MaxItems=1)
      printYellow('New access key is functional after %.0d seconds     '%diff_seconds(start_time))
      return True
    except client.exceptions.ClientError as e:
      if vars(e)['response']['Error']['Code']=='InvalidClientTokenId':
        print("  Waiting for new Access Key to work: %.0d seconds\r"%diff_seconds(start_time),end='')
    sleep(1)

def get_access_keys(access_key_id,access_key_secret):
  keys=[]
  client = boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=access_key_secret)
  try:
      keys_json = client.list_access_keys(MaxItems=10)
  except client.exceptions.ClientError as e:
    if vars(e)['response']['Error']['Code']=='AccessDenied':
      printRed("Error listing access keys: Access denied. Please contact admin\n")
    elif vars(e)['response']['Error']['Code']=='InvalidClientTokenId':
      printRed('Error listing access keys: Current used Access key is invalid\n')
    else:
      printRed(e)
    return False
  except Exception as e:
    printRed("Unknown error: %s"%e)
    return []

  for key in keys_json['AccessKeyMetadata']:
    keys.append(key['AccessKeyId'])
    
  return keys

def create_access_key(access_key_id,access_key_secret):
  try:
    client = boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=access_key_secret)
    access_key_json = client.create_access_key()
    return [access_key_json['AccessKey']['AccessKeyId'],access_key_json['AccessKey']['SecretAccessKey']]
  except client.exceptions.LimitExceededException:
    printRed("Error: maximum number of access keys allowed")
  except client.exceptions.ClientError as e:
    if vars(e)['response']['Error']['Code']=='AccessDenied':
      printRed("Error creating new access key: Access denied. Please contact admin\n")
    elif vars(e)['response']['Error']['Code']=='InvalidClientTokenId':
      printRed('Error listing access keys: Current used Access key is invalid\n')
    else:
      print(e)
    return False
  return ['','']
  
def delete_access_key(access_key_id,access_key_secret,delete_key_id):
  try:
    client = boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=access_key_secret)
    response = client.delete_access_key(AccessKeyId=delete_key_id)
    return True
  except client.exceptions.ClientError as e:
    if vars(e)['response']['Error']['Code']=='AccessDenied':
      printRed("Error Deleting access key %s : Access denied. Please contact admin\n"%delete_key_id)
    elif vars(e)['response']['Error']['Code']=='InvalidClientTokenId':
      printRed('Error listing access keys: Current used Access key is invalid\n')
    else:
      printRed(e)
    return False

def get_profiles(credentials_file_path):
  profiles=[]
  credentials_data=get_credentials_data(credentials_file_path)
  for profile in credentials_data.keys():
    if profile.lower()!='default':
      profiles.append(profile)
  return profiles

def print_profiles(credentials_file_path):
  try:
    profiles=get_profiles(credentials_file_path)
    if profiles:
      printGreen("Available profiles:")
      for profile in profiles:
        print("\t%s"%profile)
      print()
    else:
      printRed("Couldn't find any profiles in credentials file: %s\n"%credentials_file_path)
  except:
    pass
# ======================================================
#  Main
# ======================================================
def main():
  prog_name=sys.argv[0]
  # Argument parser info 
  parser = argparse.ArgumentParser()
  parser = argparse.ArgumentParser(description='This tool can be used to rotate AWS access keys', formatter_class=argparse.RawDescriptionHelpFormatter)
  parser.add_argument('--profile','-p',  help='Use --profile to specify which profile is going to be used for Access Keys rotation\nThis can be used with --force to automate key rotation accross multiple accounts', default='')
  parser.add_argument('--config','-c',  help='Use --config to use a custom credentials file. default is ~/.aws/credentials', default='~/.aws/credentials')
  parser.add_argument('--force','-f',  help='force keys rotation without asking questions', default=False, action='store_true')
  parser.add_argument('--all','-a',  help='Rotate all profiles in credentials file', default=False, action='store_true')
  
  args = parser.parse_args()
  profile=args.profile
  credentials_file_path=os.path.expanduser(args.config)
  if not profile and not args.all:
    parser.print_help()
    print()
    print_profiles(credentials_file_path)
  else:
    if args.all:
      profiles=get_profiles(credentials_file_path)
      printGreen("Rotating all profiles:")
      for profile in profiles:
          print("\t%s"%profile)
      print()    
    else:
      profiles=[profile]

    for profile in profiles:
      current_keys=get_current_access_keys(credentials_file_path,profile)
      if current_keys:
        [current_access_key_id,current_access_key_secret]=current_keys
        access_keys=get_access_keys(current_access_key_id,current_access_key_secret)
        if access_keys:
          printBlue("AWS Profile           : ",new_line=False)
          print(profile)
          printBlue("Current Access Key ID : ",new_line=False)
          print(current_access_key_id)
          if len(access_keys)>1:
            printYellow("Multiple keys found. The unused one will be deleted")
          if not args.force and not ask('Are you sure you want to rotate the access keys?'):
            printRed('\nCanceled..\n')
          else:
            failed=False
            if len(access_keys)>1:
              for key in access_keys:
                if key!=current_access_key_id:
                  if delete_access_key(current_access_key_id,current_access_key_secret,key):
                    printGreen("Deleted unused key    : ",new_line=False)
                    print(key)
                  else:
                    failed=True
            if not failed:
              access_keys=create_access_key(current_access_key_id,current_access_key_secret)
              if access_keys:
                [access_key_id,access_key_secret]=access_keys
                if access_key_id:
                  printGreen("New Key Created       : ",new_line=False)
                  print(access_key_id)
                  test_access_keys(access_key_id,access_key_secret)
                  backup_credentials_file(credentials_file_path)
                  if update_new_access_key(credentials_file_path,profile,access_key_id,access_key_secret):
                    if delete_access_key(current_access_key_id,current_access_key_secret,current_access_key_id):
                      printGreen("Deleted old key       : ",new_line=False)
                      print(current_access_key_id)
                      printGreen('\nFinished!\n')
                    
# ======================================================
if __name__ == '__main__':
  try:
    main()
  except KeyboardInterrupt:
    printRed("\r  \nInterrupted by Ctrl+C - Avoid doing this! \n")
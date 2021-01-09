# AWS Safe Access Tool
Your IP Address changes occasionaly when you move between Wifi hotspots.
Even if you're connected to the same network, most Internet connections use Dynamic IP Address, so it frequently changes.
When you have instance which you want to access directly and without VPN you have two options:
- Access the AWS Console and add a rule to your Instance's Security Group each time you have a different IP Address
- Open your Instance to the Internet (0.0.0.0/0).

Lazy developers often go to the second option.

This tool can be used to grant access to public instances on AWS for your current external IP address, or to quicly access instances via SSH - Without going to the AWS Console.
The quick SSH feature has an extra safety feature which removes the added rule a few seconds after connecting to the Instance.

**Note of advice** - This tool should only be used for testing, development and research environments, and should never be used in Production environments. You should use a Firewall or at least a NAT Gateway to restrict access from the internet to your internal instances.


# Configuration
- Copy the script to your scripts folder on your laptop
- Add an alias in your `.bash_profile` file to the script path: e.g. `alias acc='/path/to/script'`.

# What access does this tool require:
The policies folder contains two different policies which can be used and modified to allow several levels of access control:
- **enable-all-users-access-to-all-resources-policy.json** - When this policy is attached to any IAM User, Group or Role it allows adding/removing/modifying **all security groups**, as well as launch all instances.
- **enabled-all-users-access-tagged-resources-policy.json** - This is the more secure option. This policy allows the access mentioned above only to Security Groups and Instances with **SafeAccess** Tag set to **True.**

> If you don't want to allow Instance launching capabilities, remove the ec2:StartInstances action from the policy
#### Grant/Revoke your External IP address access to instances:
- The scripts adds or removes a rule from the Instance's Security Group (The script doesn't work well with multiple security groups, so only one Security Group should be attached to each instance - It's best practice anyway)
- The script adds a description with the user name in it, so if the IP changes the old rule is detected and deleted, and a new rule is created with the current IP


#### SSH Access Sequence:
- The script starts the instance in case it's stopped
- Adds a rule to the instance's Security Group to allow your External IP address access via port 22 (or other specified port)
- If -d argument is used the rule is removed a few seconds after initial SSH connection - Safer than VPN


To refer to an instance you can write only partial data of: Instance ID, Instance Name, Public IP, State.
If there are mulitiple matching instances, a choice will be presented

### Examples:
#### Access Granting/Revoking Examples:

|  Instance ID |  Instance Name | Public IP    |  State       |
| ------------ | ------------   | ------------ | ------------ |
|  i-ab123456  |  app-server    | 1.1.1.1      |  running     |


- Grant TCP 80 access to instance:
```
acc app tcp 80
acc i-ab tcp 80
acc 1.1.1 tcp 80
acc runn tcp 80
```
- Revoke UDP 53 access to instance : `acc serv udp 53 -r`

- Grant ANY access to instance: `acc app any`

#### SSH Access Examples:
- Access using OS username and id_rsa key: `acc -s app`
- Access using user Ubuntu and custom key: `acc -s ubuntu@app -i key.pem`
- Access using user Ubuntu and custom key: `acc -s app -u ubuntu -i key.pem`
- Access using user Ubuntu, custom port, and custom key: `acc -s ubuntu@1.1 -p 10443 -i key.pem`


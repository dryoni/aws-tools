# SG Tool  

This tool can be used to find ALL information related to a Security Group:  

- Inbound + Outbound Rules
- Attached Resources
- References in other SGs


## Python Virtual Environment Setup (Linux)  

**Create the Virtual Environment (Example):**  
python3 -m venv ~/projects/aws-tools/sg-tool/v-env  

**Activate the Virtual Environment (Example):**  
source ~/projects/aws-tools/sg-tool/v-env/bin/activate  

**Generate Requirements for project:**  
To create requirements.txt:  

1) Setup virtual environment  
2) Install all python packages  
   Example:  
~/projects/aws-tools/sg-tool/v-env/bin/pip3 install <PACKAGE_NAME>
3) Note: Make sure to upgrade pip  
~/projects/aws-tools/sg-tool/v-env/bin/pip3 install --upgrade pip  
4) run:  
[Path to Virtual Environment Bin Directory]/pip3 freeze > requirements.txt  
Example (Linux):  
~/projects/aws-tools/sg-tool/v-env/bin/pip3 freeze > requirements.txt  

**Install the Requirements/Dependancies (Example):**  
~/projects/aws-tools/sg-tool/v-env/bin/pip3 install -r requirements.txt  

**Example usage:**  

**Template:**  

`./sg.py <SECURITY_GROUP_ID>`

**Example Call:**  

`./sg.py sg-abc123456`  


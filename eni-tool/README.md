# ENI Tool
This tool can be used to find the resource that is using a specific IP address, or all resources using network interfaces  


## Python Virtual Environment Setup (Linux)  

**Create the Virtual Environment (Example):**  
python3 -m venv ~/projects/aws-tools/eni-tool/v-env  

**Activate the Virtual Environment (Example):**  
source ~/projects/aws-tools/eni-tool/v-env/bin/activate  

**Generate Requirements for project:**  
To create requirements.txt:  

1) Setup virtual environment  
2) Install all python packages  
   Example:  
~/projects/aws-tools/eni-tool/v-env/bin/pip3 install <PACKAGE_NAME>
3) Note: Make sure to upgrade pip  
~/projects/aws-tools/eni-tool/v-env/bin/pip3 install --upgrade pip  
4) run:  
[Path to Virtual Environment Bin Directory]/pip3 freeze > requirements.txt  
Example (Linux):  
~/projects/aws-tools/eni-tool/v-env/bin/pip3 freeze > requirements.txt  

**Install the Requirements/Dependancies (Example):**  
~/projects/aws-tools/eni-tool/v-env/bin/pip3 install -r requirements.txt  

**Example usage:**  

**Template:**  

`./eni.py <IP_ADDRESS>`

**Example Call:**  

`./eni.py 192.168.10.10`  
`./eni.py all`  



# Python-Security

This is a Python Script repo with a focus on DevSecOps. 
There are two automations: 
1. **SQS Scanner** - Python Boto3 script, wrapped in a Docker container, automated by GitHub Actions, which main purpose is to handle SQS policies that grant permissions to external principal entities. 
2. **EC2 Automation** - A simple web app that uses IMDSv2 to collect metadata from an EC2 instance. 

# SQS Scanner
### Python Code Logic
![sqs_code_logic](./images/sqs_code_logic.png?raw=true "output")

### Workflows Description
![sqs_scanner_workflows](./images/sqs_scanner_workflows.png?raw=true "output")

## Deploy on your own
### Prerequisites
* **_An AWS account containing:_**
1. preconfigured OIDC GitHub provider and a role with fitting trust policies. 
You can use this documentation for assistance: [tutorial](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)
2. S3 Bucket

* **_A Github Environment (is created in settings --> environments) named dev that contains the following:_**
1. DOCKERHUB_USERNAME - (secret) username for your dockerhub account
2. DOCKERHUB_TOKEN - (secret) password for your dockerhub account
3. IAM_GITHUB_ACTIONS_ROLE - (secret) your role - preconfigured to your github provider. 
4. DEFAULT_REGION - (vars) str: the default region for your role 
5. FILE_PATH - (vars) str: the relative path for the log file you'd like to save the sqs that have external principal policies.
6. LOG_MODE - (vars) bool: True if you wish to run in log_mode which does not modify sqs policies. 
False if you'd like to modify the policies found as having external principal policies. 
7. S3_BUCKET - (vars) str: the bucket name for the log that contains the external SQS names. 
8. IMAGE_NAME - (vars) str: the image name for the docker container that will run the script. 
9. VERSION - (vars) str: the version name for the image. 

### Steps

After creating all prerequisites you can safely commit to main branch and the [build-and-push.yml](https://github.com/HadarNeu/DevSecOps-Pyhton/blob/main/.github/workflows/build-and-push.yml) workflow will be automatically deployed. The [scheduled-sqs-automation.yml](https://github.com/HadarNeu/DevSecOps-Pyhton/blob/main/.github/workflows/scheduled-sqs-automation.yml) workflow is scheduled to run once a day. 

### Challenges I Encountered 
* **GitHub OIDC provider-** I didn't want to use credentials as secrets in the GitHub environment because it usually means the credentials don't have any time constraint. OICD Provider combined with a role containing fitting trust policies is a pretty straightforward proccess but difficult to debug due to lack of logs. 
* **Env Vars use in Docker Container-** Locally works a certain way that doesn't work with GitHub actions. I've had to dive deep into loads of blogs until I found my current solution. Of course, this solution will probably not be used in a normal company, since K8s has ConfigMap and Secrets. 
* **Trivy -** I found that it made no sense to have a trivy test (on code/ images) without having the opportunity to view the results in a comfortable way. Eventually I ended up with the sarif file solution that sends all security results to GitHuv Security Tab. 

### What's Next?
1. **Log file beautify-** take file extention and put it in the end of the file name when pushing to s3. 
2. **Security-** Adding code testing by synk as well as image testing by trivy. 
3. **Trivy-** run trivy via trivy docker container.
4. **Unit testing-** write unit tests for the SQS Scanner. 
5. **Efficiency-** Add function that gets information from organization if the account is activated in order to make runtime more efiicient. 
6. **Implement Uplift -** uplift is a version management solution that can increase the version number in every PR/ commit to main. [uplift](https://upliftci.dev/)
7. **Jobs-** increase number of jobs in the GitHub Workflow in order to get more seperation and easier debugging.  


# EC2 Automation
## Deploy on your own
### Prerequisites
* **_An AWS account containing:_**
1. An EC2 you can connect to via SSH. 
2. Security Group that exposes port 5000 and port 22 to your IP (never to 0.0.0.0). 
3. Public networking settings including enabling IPv4. **NOT RECOMMENDED 
4. Connection to GitHub via SSH / GPG. After connection is established clone the repository to get access to the script. 
5. Install Python3 version ```3.11.4``` or higher. 
6. Install pip3 and all requirements via 
```pip install -r requirements.txt```

### Steps 
After creating all prerequisites you can safely run the script: 
```Python3 ec2-metadata-automation.py```
and the webserver will be turned on. 

Access your metadata via the browser: ```<public ip address>:5000/metadata```

It should look something like this: (pretty ugly, I know)
![alt text](./docs/images/kubectl-get-pods.png?raw=true "output")

### Challenges I Encountered 
* EC2 - As an experienced DevOps engineer with a passion for security, I found it hard working with a public EC2, feeling as it is exposed to the world and doesn't comply with any best practice whatsoever. But with a lack of budget for this task, Iv'e had to use only free resources. My solution was using my personal VPN to be the only connection available for the EC2 server. 

### What's Next?
1. Apply caching and TTL
2. Create a Dockerfile to containerize the script.  
3. Create an EKS deployment and run the web app on that cluster - deploy the app using a helm chart. 
4. Insert some html templates to make the app presentable. 
5. Create a VPC and all networking components using Terraform, in order for the app to be hosted privately. 
6. Create an OpenVPN server in order to access the EC2 server. 
7. Modify the app to present the most relevant fields in the metadata's query response. 
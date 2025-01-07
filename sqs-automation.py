from dataclasses import dataclass
import boto3
import json
from datetime import datetime
import logging
import copy
import sys
import os
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

@dataclass
class SQSPolicyData:
    def __init__(self, regions=None, account_id=None):
        self.session = boto3.Session(region_name='eu-west-1')
        self.regions = regions or self.get_all_regions()
        self.account_id = account_id or self.get_account_id()

    def get_account_id(self):
        # Use STS to get the caller identity and extract the account ID
        sts_client = self.session.client('sts')
        identity = sts_client.get_caller_identity()
        return identity['Account']
    
    def get_all_regions(self):
        """ returns a list of all AWS regions"""
        ec2 = self.session.client('ec2')
        # todo optional: return [region['RegionName'] for region in ec2.describe_regions()['Regions'] if self.is_relevant_region(region)]
        return [region['RegionName'] for region in ec2.describe_regions()['Regions']]
    
    def get_sqs_urls_per_region(self, region: str):
        """ gets a region and returns the queue url list of that region """
        queues_list = []

        try:
            sqs = self.session.client('sqs', region_name=region)
            paginator = sqs.get_paginator('list_queues')

            for page in paginator.paginate():
                if 'QueueUrls' in page:
                    for queue_url in page['QueueUrls']:
                        queues_list.append(queue_url)

            return queues_list

        except Exception as e:
            logging.error(f"Error scanning region {region}: {str(e)}")

    def get_policy(self, region: str, queue_url: str):
        """
        Gets the policy for a specific SQS queue URL in a given region.
        
        Args:
            region (str): AWS region (e.g., 'us-east-1')
            queue_url (str): Full URL of the SQS queue
            
        Returns:
            dict: JSON policy document. Empty dict if no policy exists.
            
        Raises:
            ClientError: If there's an AWS API error
            Exception: For other unexpected errors
        """
        try:
            sqs = self.session.client('sqs', region_name=region)
            
            # Get queue attributes and policy
            response = sqs.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=['Policy']
            )
            # Check if policy exists in the response
            if 'Attributes' in response and 'Policy' in response['Attributes']:
                # Parse the policy from string to JSON
                import json
                return json.loads(response['Attributes']['Policy'])
            
            # Return empty dict if no policy is set
            return {}
        
        except sqs.exceptions.ClientError as e:
            print(f"AWS Error getting policy for queue {queue_url}: {str(e)}")
            raise
        except Exception as e:
            print(f"Unexpected error getting policy for queue {queue_url}: {str(e)}")
            raise

    def get_secured_policy(self, policy_doc, queue_url: str):
        """ gets a json policy doc and returns a new object of that policy but secure"""

        # Create a deep copy of the policy document
        modified_policy = copy.deepcopy(policy_doc)
        try:
            for statement in modified_policy.get('Statement', []):
                # checking is policy external in main 
                if 'Principal' in statement:
                    statement['Principal'] = {"AWS": f"arn:aws:iam::{self.account_id}:root"}

            logging.info(f"successfully returned a secured policy")
            return modified_policy
        
        except Exception as e:
            logging.error(f"Error processing policy {queue_url}: {str(e)}")

    def is_policy_external(self, policy_doc, queue_url: str):
        """ Gets a policy json document (dictionary) and a queue_url
         and returns True if the policy allows external access and False if valid """
        
        try: 
            for statement in policy_doc.get('Statement', []):
                # checks if Principal is regex *
                if 'Principal' in statement and isinstance(statement['Principal'], str) and statement['Principal'] == "*": 
                    return True

                # if there is AWS in the Principal 
                if 'AWS' in statement['Principal']:
                    aws_principal = statement['Principal']['AWS']

                    if isinstance(aws_principal, str) and (aws_principal == "*" or not aws_principal.startswith(f"arn:aws:iam::{self.account_id}")):
                        logging.info(f"policy has external principal permissions {queue_url}")
                        return True 

                    if isinstance(aws_principal, list):
                        for principal in aws_principal: #iterate over the principals
                            if principal == "*" or (isinstance(principal, str) and not principal.startswith(f"arn:aws:iam::{self.account_id}")): 
                                logging.info(f"policy has external principal permissions {queue_url}")
                                return True 
                            
            logging.info(f"policy is valid {queue_url}")
            return False 
        
        except Exception as e:
            logging.error(f"Error processing policy {queue_url}: {str(e)}")

        
            
class SQSExternalPolicy:
    def __init__(self, s3_bucket: str, file_path: str, log_mode: bool):
        self.session = boto3.Session()
        self.s3_bucket = self.validate_s3_bucket(s3_bucket)
        self.log_mode = self._validate_log_mode(log_mode)
        self.file_path = self._validate_file_path(file_path)

        logging.info(f"log_mode is valid. Value: {self.log_mode}, type: {type(self.log_mode)}")
        logging.info(f"file_path is valid. Value: {self.file_path}, type: {type(self.file_path)}")

        
    def validate_s3_bucket(self, s3_bucket: str):
        """ this function validates the bucket name exists in the current account"""
        s3_client = self.session.client('s3')

        try:
            # List all the buckets in the account
            response = s3_client.list_buckets()
            bucket_names = [bucket['Name'] for bucket in response['Buckets']]

            # Check if the provided bucket name exists
            if s3_bucket in bucket_names and isinstance(s3_bucket, str):
                logging.info(f"Bucket '{s3_bucket}' valid and exists in the current account.")
                return s3_bucket
            else:
                logging.error(f"Bucket '{s3_bucket}' does not exist in the current account.")

        except s3_client.exceptions.NoCredentialsError:
            logging.error("Credentials not available.")
        except s3_client.exceptions.PartialCredentialsError:
            logging.error("Incomplete credentials provided.")
        except Exception as e:
            logging.error(f"An error occurred: {str(e)}")

    @staticmethod
    def _validate_log_mode(log_mode):
        if isinstance(log_mode, str):
            log_mode_test = log_mode.lower()
            if log_mode_test in ('true', 'yes', '1', 'on'):
                return True
            elif log_mode_test in ('false', 'no', '0', 'off'):
                return False
            raise ValueError(f"Invalid boolean string for log_mode: {log_mode}")
        
    @staticmethod
    def _validate_file_path(file_path):
        allowed_extensions = ['.txt', '.log', '.csv', '.md', '.json', 
            '.yml', '.yaml', '.ini', '.cfg', '.env',
            '.conf', '.properties', '.list', '.dat',
            '.out', '.tsv']
        
        _, extension = os.path.splitext(file_path)

        if extension not in allowed_extensions:
            raise ValueError(f"Invalid file extension. Allowed extensions are: {', '.join(allowed_extensions)}")
        
        if not isinstance(file_path, str):
            raise TypeError(f"Invalid file path. File path should be str")
        
        else: return file_path
            
    def modify_policy(self, region: str, queue_url: str, wanted_policy_doc):
        """
        Modifies the policy of a specified SQS queue with the provided policy document.
        
        Args:
            region (str): AWS region (e.g., 'us-east-1')
            queue_url (str): Full URL of the SQS queue
            wanted_policy_doc (dict): New policy document to apply
            
        Raises:
            ClientError: If there's an AWS API error
            Exception: For other unexpected errors
        """
        try:
            # Initialize SQS client for the specified region
            sqs_client = boto3.client('sqs', region_name=region)
            
            # Convert policy document to JSON string
            policy_string = json.dumps(wanted_policy_doc)
            
            # Set the new policy
            sqs_client.set_queue_attributes(
                QueueUrl=queue_url,
                Attributes={
                    'Policy': policy_string
                }
            )
            
        except sqs_client.exceptions.ClientError as e:
            print(f"AWS Error modifying policy for queue {queue_url}: {str(e)}")
            raise
        except Exception as e:
            print(f"Unexpected error modifying policy for queue {queue_url}: {str(e)}")
            raise

        logging.info(f"Successfully modified policy of {queue_url} to a secure policy") 

    def add_sqs_name_to_file(self, queue_url: str, region: str):
        """ If a file does not exist, create a new file and write the queue name into it"""

        queue_name = queue_url.split('/')[-1]
        new_data = f"{queue_name} in region {region}"

        # Make sure no data is getting overritten / duplicated
        try:
            with open(self.file_path, 'a+') as file:
                # Read existing content and strip newline characters
                file.seek(0)  # Ensure we're reading from the beginning of the file
                existing_data = [line.strip() for line in file.readlines()]

                if new_data not in existing_data:
                    file.write(f"{new_data}\n")
                    logging.info("New sqs name added to the file successfully")
                else:
                    logging.info("sqs name already exists in the file")

        except FileNotFoundError as e:
            logging.error(f"File not found {str(e)}")

    def upload_file_to_s3(self):
        """Upload log file to S3"""
        try:
            s3 = self.session.client('s3')
            timestamp = datetime.now().strftime('%m-%d-%Y_%H-%M-%S')
            filename = os.path.basename(self.file_path) # strip path is exists
            key = f'{filename}-{timestamp}'
            
            s3.upload_file(self.file_path, self.s3_bucket, key)
            logging.info(f"Log file uploaded to s3://{self.s3_bucket}/{key}")
            
        except Exception as e:
            logging.error(f"Error uploading log to S3: {str(e)}")

    def clenup_sqs_log_file(self):
        """
        Cleans up (empties) the SQS log file if it exists.
        
        The function will:
        1. Check if the log file exists
        2. Empty it if it exists
        3. Log the cleanup action
        
        Raises:
            IOError: If there are permission issues or other IO problems
        """
        try:
            if hasattr(self, 'file_path') and os.path.exists(self.file_path):
                with open(self.file_path, 'w') as f:
                    f.truncate(0)
                logging.info(f"Successfully cleaned up SQS log file: {self.file_path}")
            else:
                logging.debug("No SQS log file found to clean up")
        except IOError as e:
            logging.error(f"Failed to clean up SQS log file: {str(e)}")
            raise

    def run(self):
        logging.info("Starting SQS policy scan")
        sqsData = SQSPolicyData()
        queue_urls = []
        policy  = {}
        modified_policy = {}
        queue_url = ""

        #before strating the scan, we should clean up the log file if it exists. 
        self.clenup_sqs_log_file()

        # Scan regions sequentially
        regions = sqsData.get_all_regions()
        for region in regions:
            logging.info(f"Scanning region: {region}")
    
            #if there's no sqs in the region, move on to next region
            if not sqsData.get_sqs_urls_per_region(region): 
                logging.info(f"No sqs in the region: {region}")
                continue

            queue_urls = sqsData.get_sqs_urls_per_region(region)

            for queue_url in queue_urls:
                policy = sqsData.get_policy(region, queue_url)
                if sqsData.is_policy_external(policy, queue_url):
                    if not self.log_mode:
                        modified_policy  =  sqsData.get_secured_policy(policy, queue_url)  
                        self.modify_policy(region, queue_url, modified_policy)

                    # Upload log file to S3
                    self.add_sqs_name_to_file(queue_url, region)
            
        self.upload_file_to_s3()
        logging.info("Scan complete")



def main():
    # Load environment variables from the .env file
    load_dotenv()

    # Access environment variables
    s3_bucket = os.getenv('S3_BUCKET')
    sqs_file_path = os.getenv('FILE_PATH')
    log_mode = os.getenv('LOG_MODE')

    scanner = SQSExternalPolicy(s3_bucket=s3_bucket, file_path=sqs_file_path, log_mode=log_mode)
    scanner.run()


if __name__ == "__main__":
    main()

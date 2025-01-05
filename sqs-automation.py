import boto3
import json
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    filename='log.txt',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

class SQSPolicyScanner:
    def __init__(self, s3_bucket):
        self.s3_bucket = s3_bucket
        self.session = boto3.Session()
        self.account_id = self.get_account_id()

    def get_account_id(self):
        # Use STS to get the caller identity and extract the account ID
        sts_client = self.session.client('sts')
        identity = sts_client.get_caller_identity()
        return identity['Account']
        
    def get_all_regions(self):
        # Get list of all AWS regions
        ec2 = self.session.client('ec2')
        return [region['RegionName'] for region in ec2.describe_regions()['Regions']]

    def modify_policy_in_place(self, policy_doc):
        #Modify the existing policy to replace external principals with account principal
        modified = False
        
        for statement in policy_doc.get('Statement', []):
            if 'Principal' in statement:
                # Handle string principal
                if isinstance(statement['Principal'], str): #if the statement is a string 
                    if statement['Principal'] == "*": #if the value is * 
                        statement['Principal'] = {"AWS": f"arn:aws:iam::{self.account_id}:root"}
                        modified = True
                    continue

                # Handle AWS principals
                if 'AWS' in statement['Principal']:
                    aws_principal = statement['Principal']['AWS']
                    
                    # Handle list of principals
                    if isinstance(aws_principal, list):
                        for i, p in enumerate(aws_principal): #iterate over the principals
                            if p == "*" or (
                                isinstance(p, str) and  # are you a string? 
                                not p.startswith(f"arn:aws:iam::{self.account_id}") #do you belong to my account?
                            ):
                                aws_principal[i] = f"arn:aws:iam::{self.account_id}:root"
                                modified = True
                    
                    # Handle single principal
                    elif aws_principal == "*" or (
                        isinstance(aws_principal, str) and 
                        not aws_principal.startswith(f"arn:aws:iam::{self.account_id}")
                    ):
                        statement['Principal']['AWS'] = f"arn:aws:iam::{self.account_id}:root"
                        modified = True

        return modified


    def process_queue(self, region, queue_url):
        #Process a single queue
        try:
            sqs = self.session.client('sqs', region_name=region)
            
            # Get queue attributes and policy
            response = sqs.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=['Policy']
            )
            
            if 'Policy' in response['Attributes']:
                policy_str = response['Attributes']['Policy']
                policy_doc = json.loads(policy_str)
                
                # Modify policy in place
                if self.modify_policy_in_place(policy_doc):
                    queue_name = queue_url.split('/')[-1]
                    logging.info(f"External access found in queue: {queue_name} (Region: {region})")
                    
                    # Update the queue with modified policy
                    sqs.set_queue_attributes(
                        QueueUrl=queue_url,
                        Attributes={
                            'Policy': json.dumps(policy_doc)
                        }
                    )
                    logging.info(f"Policy updated for queue: {queue_name}")
                    
        except Exception as e:
            logging.error(f"Error processing queue {queue_url}: {str(e)}")

    def scan_region(self, region):
        #Scan all queues in a region
        try:
            sqs = self.session.client('sqs', region_name=region)
            paginator = sqs.get_paginator('list_queues')
            
            for page in paginator.paginate():
                if 'QueueUrls' in page:
                    for queue_url in page['QueueUrls']:
                        self.process_queue(region, queue_url)
                        
        except Exception as e:
            logging.error(f"Error scanning region {region}: {str(e)}")

    def upload_log_to_s3(self):
        #Upload log file to S3
        try:
            s3 = self.session.client('s3')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            key = f'sqs_policy_scan_{timestamp}.log'
            
            s3.upload_file('log.txt', self.s3_bucket, key)
            logging.info(f"Log file uploaded to s3://{self.s3_bucket}/{key}")
            
        except Exception as e:
            logging.error(f"Error uploading log to S3: {str(e)}")

    def run(self):
        #Main execution method
        logging.info("Starting SQS policy scan")
        
        # Get account ID if not provided
        if not self.account_id:
            sts = self.session.client('sts')
            self.account_id = sts.get_caller_identity()['Account']
        
        # Scan regions sequentially
        regions = self.get_all_regions()
        for region in regions:
            logging.info(f"Scanning region: {region}")
            self.scan_region(region)
        
        # Upload log file to S3
        self.upload_log_to_s3()
        logging.info("Scan complete")


def main():
    S3_BUCKET = 's3-sqs-modifier-test-bucket'
    
    scanner = SQSPolicyScanner(s3_bucket=S3_BUCKET)
    scanner.run()


if __name__ == "__main__":
    main()

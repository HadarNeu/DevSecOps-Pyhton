import os
import sys
import copy
import json
import logging
import boto3
from datetime import datetime
from dataclasses import dataclass
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

class SQSPolicyData:
    def __init__(self, regions=None, account_id=None):
        """
        Initializes the SQSPolicyData object.
        It retrieves AWS account ID via STS, and collects the list of all AWS regions unless
        they are manually provided.

        Args:
            regions (list, optional): List of AWS region names.
            account_id (str, optional): AWS account ID.
        """
        self.session = boto3.Session()
        self.regions = regions or self.get_all_regions()
        self.account_id = account_id or self._get_account_id()

    def _get_account_id(self):
        """
        Uses STS to retrieve the AWS account ID for the current session.

        Returns:
            str: AWS account ID.
        """
        sts_client = self.session.client('sts')
        identity = sts_client.get_caller_identity()
        return identity['Account']

    def get_all_regions(self):
        """
        Retrieves a list of all AWS regions using the EC2 client.

        Returns:
            list: List of AWS region names.
        """
        ec2 = self.session.client('ec2')
        return [region['RegionName'] for region in ec2.describe_regions()['Regions']]

    def get_sqs_urls_per_region(self, region: str):
        """
        Returns a list of SQS queue URLs in the specified region.

        Args:
            region (str): The AWS region to scan for SQS queues.

        Returns:
            list: List of SQS queue URLs. Empty if none found or an error occurs.
        """
        queues_list = []
        try:
            sqs = self.session.client('sqs', region_name=region)
            paginator = sqs.get_paginator('list_queues')

            for page in paginator.paginate():
                if 'QueueUrls' in page:
                    queues_list.extend(page['QueueUrls'])

            return queues_list

        except Exception as e:
            logging.error(f"Error scanning region {region}: {str(e)}")
            return []

    def get_policy(self, region: str, queue_url: str):
        """
        Retrieves the policy for a specific SQS queue URL in a given region.

        Args:
            region (str): AWS region
            queue_url (str): Full URL of the SQS queue.

        Returns:
            dict: JSON policy document. Empty dict if no policy exists.

        Raises:
            ClientError: If there's an AWS API error.
            Exception: For other unexpected errors.
        """
        try:
            sqs = self.session.client('sqs', region_name=region)
            response = sqs.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=['Policy']
            )
            if 'Attributes' in response and 'Policy' in response['Attributes']:
                return json.loads(response['Attributes']['Policy'])
            return {}
        except sqs.exceptions.ClientError as e:
            print(f"AWS Error getting policy for queue {queue_url}: {str(e)}")
            raise
        except Exception as e:
            print(f"Unexpected error getting policy for queue {queue_url}: {str(e)}")
            raise

    def get_secured_policy(self, policy_doc, queue_url: str):
        """
        Given a policy document, returns a modified version of that document
        to ensure it references only the current AWS account as a Principal.

        Args:
            policy_doc (dict): Original policy document (JSON/dict).
            queue_url (str): Full URL of the SQS queue (for logging).

        Returns:
            dict: Modified (secured) policy document or None if there's an error.
        """
        modified_policy = copy.deepcopy(policy_doc)
        try:
            for statement in modified_policy.get('Statement', []):
                if 'Principal' in statement:
                    # Replace any external principal with the root of this account
                    statement['Principal'] = {"AWS": f"arn:aws:iam::{self.account_id}:root"}

            logging.info("Successfully returned a secured policy.")
            return modified_policy
        except Exception as e:
            logging.error(f"Error processing policy for queue {queue_url}: {str(e)}")
            return None

    def is_policy_external(self, policy_doc, queue_url: str):
        """
        Checks if a policy allows external access (principal is "*" or an AWS principal
        that does not match the current account ID).

        Args:
            policy_doc (dict): Policy document (JSON/dict).
            queue_url (str): Full URL of the SQS queue (for logging).

        Returns:
            bool: True if the policy is external, False otherwise.
        """
        try:
            for statement in policy_doc.get('Statement', []):
                # Check if principal is literally "*"
                if 'Principal' in statement and isinstance(statement['Principal'], str):
                    if statement['Principal'] == "*":
                        return True

                # Check if 'AWS' is in the principal
                if 'Principal' in statement and 'AWS' in statement['Principal']:
                    aws_principal = statement['Principal']['AWS']

                    # test for a singular value (is the value a string?)
                    if isinstance(aws_principal, str):
                        if aws_principal == "*" or not aws_principal.startswith(f"arn:aws:iam::{self.account_id}"):
                            logging.info(f"Policy has external principal permissions {queue_url}")
                            return True

                    # test for multiple values (is the value a list?)
                    elif isinstance(aws_principal, list):
                        for principal in aws_principal:
                            if principal == "*" or (
                                isinstance(principal, str) and not principal.startswith(f"arn:aws:iam::{self.account_id}")
                            ):
                                logging.info(f"Policy has external principal permissions {queue_url}")
                                return True

            logging.info(f"Policy is valid {queue_url}")
            return False
        except Exception as e:
            logging.error(f"Error processing policy for queue {queue_url}: {str(e)}")
            return False


class SQSExternalPolicy:
    def __init__(self, s3_bucket: str, file_path: str, log_mode: bool):
        """
        Initializes the SQSExternalPolicy object, which handles scanning/modifying
        SQS policies, logging affected queues to a file, and uploading that file to S3.

        Args:
            s3_bucket (str): The name of the S3 bucket for log file upload.
            file_path (str): Path to the log file.
            log_mode (bool): Whether to log queues with external policies (True)
                             without modifying them, or to modify them (False).
        """
        self.session = boto3.Session()
        self.s3_bucket = self._validate_s3_bucket(s3_bucket)
        self.log_mode = self._validate_log_mode(log_mode)
        self.file_path = self._validate_file_path(file_path)

        logging.info(f"log_mode is valid. Value: {self.log_mode}, type: {type(self.log_mode)}")
        logging.info(f"file_path is valid. Value: {self.file_path}, type: {type(self.file_path)}")

    def _validate_s3_bucket(self, s3_bucket: str):
        """
        Validates that the specified S3 bucket name is a string and exists in the current account.

        Args:
            s3_bucket (str): S3 bucket name to validate.

        Returns:
            str or None: The S3 bucket name if it exists; otherwise None.
        """
        s3_client = self.session.client('s3')
        try:
            response = s3_client.list_buckets()
            bucket_names = [bucket['Name'] for bucket in response['Buckets']]

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
        return None

    @staticmethod
    def _validate_log_mode(log_mode):
        """
        Validates/logically parses the log_mode argument (supports str or bool).

        Args:
            log_mode: Value that should parse to a boolean.

        Returns:
            bool: True/False based on the passed value.

        Raises:
            ValueError: If the input string cannot be converted to a boolean.
        """
        if isinstance(log_mode, str):
            lm_lower = log_mode.lower()
            if lm_lower in ('true', 'yes', '1', 'on'):
                return True
            elif lm_lower in ('false', 'no', '0', 'off'):
                return False
            raise ValueError(f"Invalid boolean string for log_mode: {log_mode}")
        return log_mode

    @staticmethod
    def _validate_file_path(file_path):
        """
        Ensures the file path has a valid extension and is a string.

        Args:
            file_path (str): Path to the file.

        Returns:
            str: The file path if valid.

        Raises:
            ValueError: If the file extension is not allowed.
            TypeError: If file_path is not a string.
        """
        allowed_extensions = [
            '.txt', '.log', '.csv', '.md', '.json',
            '.yml', '.yaml', '.ini', '.cfg', '.env',
            '.conf', '.properties', '.list', '.dat',
            '.out', '.tsv'
        ]

        if not isinstance(file_path, str):
            raise TypeError("Invalid file path. File path should be str")

        _, extension = os.path.splitext(file_path)
        if extension not in allowed_extensions:
            raise ValueError(
                f"Invalid file extension. Allowed extensions are: {', '.join(allowed_extensions)}"
            )
        return file_path

    def modify_policy(self, region: str, queue_url: str, wanted_policy_doc):
        """
        Modifies the policy of a specified SQS queue with the provided policy document.

        Args:
            region (str): AWS region 
            queue_url (str): Full URL of the SQS queue.
            wanted_policy_doc (dict): New policy document to apply.

        Raises:
            ClientError: If there's an AWS API error.
            Exception: For other unexpected errors.
        """
        try:
            sqs_client = boto3.client('sqs', region_name=region)
            policy_string = json.dumps(wanted_policy_doc)
            sqs_client.set_queue_attributes(
                QueueUrl=queue_url,
                Attributes={'Policy': policy_string}
            )
        except sqs_client.exceptions.ClientError as e:
            print(f"AWS Error modifying policy for queue {queue_url}: {str(e)}")
            raise
        except Exception as e:
            print(f"Unexpected error modifying policy for queue {queue_url}: {str(e)}")
            raise

        logging.info(f"Successfully modified policy of {queue_url} to a secure policy.")

    def add_sqs_name_to_file(self, queue_url: str, region: str):
        """
        If the specified file doesn't exist, creates it. Then appends the SQS queue name
        and region to the file if it's not already present.

        Args:
            queue_url (str): Full URL of the SQS queue.
            region (str): AWS region of the queue.
        """
        queue_name = queue_url.split('/')[-1]
        new_data = f"{queue_name} in region {region}"

        try:
            with open(self.file_path, 'a+') as file:
                file.seek(0)
                existing_data = [line.strip() for line in file.readlines()]

                if new_data not in existing_data:
                    file.write(f"{new_data}\n")
                    logging.info("New SQS name added to the file successfully.")
                else:
                    logging.info("SQS name already exists in the file.")
        except FileNotFoundError as e:
            logging.error(f"File not found: {str(e)}")

    def upload_file_to_s3(self):
        """
        Uploads the log file to S3 with a timestamp appended to the filename.
        """
        try:
            s3_client = self.session.client('s3')
            timestamp = datetime.now().strftime('%m-%d-%Y_%H-%M-%S')
            filename = os.path.basename(self.file_path)
            key = f'{filename}-{timestamp}'

            s3_client.upload_file(self.file_path, self.s3_bucket, key)
            logging.info(f"Log file uploaded to s3://{self.s3_bucket}/{key}")
        except Exception as e:
            logging.error(f"Error uploading log to S3: {str(e)}")

    def cleanup_sqs_log_file(self):
        """
        Cleans up (empties) the SQS log file if it exists.

        The function will:
        1. Check if the log file exists.
        2. Empty it if it exists.
        3. Log the cleanup action.

        Raises:
            Exception: If there are permission issues or other IO problems.
        """
        try:
            if hasattr(self, 'file_path') and os.path.exists(self.file_path):
                with open(self.file_path, 'w') as f:
                    f.truncate(0)
                logging.info(f"Successfully cleaned up SQS log file: {self.file_path}")
            else:
                logging.debug("No SQS log file found to clean up.")
        except Exception as e:
            logging.error(f"Failed to clean up SQS log file: {str(e)}")
            raise

    def run(self):
        """
        Main method to:
        1. Clean up the existing SQS log file (if any).
        2. Get all regions from SQSPolicyData.
        3. For each region, retrieve all SQS queue URLs.
        4. For each queue, check if the policy is external.
           - If not in log mode, modify it to secure it.
           - Log the queue name/region to the file if external.
        5. Upload the resulting log file to S3.
        """
        logging.info("Starting SQS policy scan.")
        sqs_data = SQSPolicyData()

        # Clean up the log file before starting
        self.cleanup_sqs_log_file()

        # Retrieve all regions and scan them sequentially
        regions = sqs_data.get_all_regions()
        for region in regions:
            logging.info(f"Scanning region: {region}")

            queue_urls = sqs_data.get_sqs_urls_per_region(region)
            if not queue_urls:
                logging.info(f"No SQS in the region: {region}")
                continue

            for queue_url in queue_urls:
                policy = sqs_data.get_policy(region, queue_url)
                if sqs_data.is_policy_external(policy, queue_url):
                    if not self.log_mode:
                        secured_policy = sqs_data.get_secured_policy(policy, queue_url)
                        if secured_policy:
                            self.modify_policy(region, queue_url, secured_policy)
                    self.add_sqs_name_to_file(queue_url, region)

        self.upload_file_to_s3()
        logging.info("Scan complete.")


def main():
    """
    Main entry point. Loads environment variables from .env, initializes SQSExternalPolicy,
    and starts the scan run.
    """
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

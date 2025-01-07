from flask import Flask, jsonify
import requests

app = Flask(__name__)

# Function to get metadata using IMDSv2
def get_instance_metadata():
    # Step 1: Get a token from the Instance Metadata Service
    token_url = "http://169.254.169.254/latest/api/token"
    headers = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}  # Token valid for 6 hours
    token_response = requests.put(token_url, headers=headers)
    
    if token_response.status_code != 200:
        return {"error": "Failed to retrieve token"}, 500
    
    token = token_response.text

    # Step 2: Use the token to access the metadata
    metadata_url = "http://169.254.169.254/latest/meta-data/"
    metadata_headers = {"X-aws-ec2-metadata-token": token}
    
    # Fetching specific metadata fields
    instance_id = requests.get(metadata_url + "instance-id", headers=metadata_headers).text
    availability_zone = requests.get(metadata_url + "placement/availability-zone", headers=metadata_headers).text
    private_ip = requests.get(metadata_url + "local-ipv4", headers=metadata_headers).text
    subnet_id = requests.get(metadata_url + "network/interfaces/macs/", headers=metadata_headers).text

    return {
        "Instance ID": instance_id,
        "Availability Zone": availability_zone,
        "Private IPv4 Address": private_ip,
        "Subnet ID": subnet_id
    }

@app.route('/metadata', methods=['GET'])
def metadata():
    instance_metadata = get_instance_metadata()
    return jsonify(instance_metadata)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

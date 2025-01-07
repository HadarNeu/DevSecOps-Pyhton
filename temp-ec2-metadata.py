from flask import Flask, jsonify
import requests

# Initialize Flask application
app = Flask(__name__)

# Define the base URL for the EC2 metadata service
BASE_URL = "http://169.254.169.254/latest"

def imdsv2_authentication():
    """
    Retrieves EC2 instance metadata using IMDSv2 (Instance Metadata Service v2).
    IMDSv2 is a session-oriented method that enhances security through the use of session tokens.
    
    Returns:
        dict: Dictionary containing instance metadata or error message
        int: HTTP status code
    """
    try:
        # Step 1: Obtain a session token that is valid for 6 hours
        token_url = f"{BASE_URL}/api/token"
        token_headers = {
            "X-aws-ec2-metadata-token-ttl-seconds": "21600" 
        }
        
        token_response = requests.put(token_url, headers=token_headers, timeout=2)
        
        if token_response.status_code != 200:
            return {
                "error": "Failed to retrieve token",
                "status_code": token_response.status_code
            }, 500
        
        token = token_response.text

        # Step 2: Prepare headers for metadata requests
        metadata_headers = {"X-aws-ec2-metadata-token": token}

        return metadata_headers, 200

    except requests.exceptions.RequestException as e:
        return {
            "error": f"Failed to authenticate: {str(e)}",
            "details": "This might happen if the code is not running on an EC2 instance"
        }, 500
    except Exception as e:
        return {
            "error": f"Unexpected error: {str(e)}"
        }, 500
        
def get_instance_metadata(metadata_headers):
    try:
        # Fetch specific metadata fields
        metadata_fields = {
            "Instance ID": "instance-id",
            "Availability Zone": "placement/availability-zone",
            "Private IPv4 Address": "local-ipv4",
            "Subnet ID": "network/interfaces/macs/"
        }
        
        metadata = {}

        # Fetch each metadata field
        for display_name, endpoint in metadata_fields.items():
            response = requests.get(
                f"{BASE_URL}/meta-data/{endpoint}",
                headers=metadata_headers,
                timeout=2
            )
            if response.status_code == 200:
                metadata[display_name] = response.text
            else:
                metadata[display_name] = f"Error fetching {display_name}"

        return metadata, 200

    except requests.exceptions.RequestException as e:
        return {
            "error": f"Failed to retrieve metadata: {str(e)}",
            "details": "This might happen if the code is not running on an EC2 instance"
        }, 500
    except Exception as e:
        return {
            "error": f"Unexpected error: {str(e)}"
        }, 500

@app.route('/metadata', methods=['GET'])
def metadata():
    """
    Flask route handler for /metadata endpoint.
    Returns EC2 instance metadata as JSON.
    
    Returns:
        Response: JSON response containing instance metadata or error message
    """
    metadata_headers, status_code = imdsv2_authentication()
    instance_metadata, status_code = get_instance_metadata(metadata_headers)
    return jsonify(instance_metadata), status_code

if __name__ == '__main__':
    app.run(
        host='0.0.0.0', 
        port=5000,       
        debug=False      
    )
from flask import Flask, jsonify
import requests

# Initialize Flask application
app = Flask(__name__)

# Define the base URL for the EC2 metadata service
BASE_URL = "http://169.254.169.254/latest"

def imdsv2_authentication():
    """
    Authenticates with the EC2 Instance Metadata Service v2 (IMDSv2).
    
    This function handles the authentication process for IMDSv2, which is required
    before accessing any metadata. It obtains a session token that remains valid
    for 6 hours and can be used for subsequent metadata requests.

    Returns:
        dict: matadata headers including token
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
    """
    Retrieves specific EC2 instance metadata using authenticated headers.
    
    This function fetches a predefined set of metadata fields from the EC2 instance
    using the provided authentication headers. It makes individual requests for each
    metadata field to build a comprehensive metadata dictionary.
    
    Args:
        metadata_headers (dict): Headers containing the IMDSv2 token for authentication
        
    Returns:
        tuple: A tuple containing:
            - dict: Either the collected metadata or error information
            - int: HTTP status code (200 for success, 500 for errors)
    """
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
    
    This endpoint performs a two-step process:
    1. Authenticates with IMDSv2 to get a session token
    2. Uses the token to retrieve EC2 instance metadata
    
    Returns:
        Response: JSON response containing instance metadata and HTTP status code
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
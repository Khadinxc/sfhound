
import yaml
import requests
import jwt
import time
from pathlib import Path

class SalesforceAuth:
    def __init__(self, config):
        """
        Initialize Salesforce authentication.
        
        Args:
            config: Either a dict containing configuration or a path to config YAML file (str)
        """
        if isinstance(config, dict):
            # Config dict passed directly (from CLI + YAML merge)
            self.config = config['salesforce']
        elif isinstance(config, str):
            # Config path passed (backward compatibility)
            with open(config, 'r') as f:
                self.config = yaml.safe_load(f)['salesforce']
        else:
            raise ValueError("config must be either a dict or a path to YAML file")
        
        self.access_token = None
        self.instance_url = None

    def authenticate(self):
        # JWT payload
        payload = {
            'iss': self.config['client_id'],
            'sub': self.config['username'],
            'aud': self.config['login_url'],
            'exp': int(time.time()) + 300
        }
        # Load private key
        with open(self.config['private_key'], 'r') as key_file:
            private_key = key_file.read()
        assertion = jwt.encode(payload, private_key, algorithm='RS256')
        url = f"{self.config['login_url']}/services/oauth2/token"
        data = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion': assertion
        }
        response = requests.post(url, data=data)
        if response.status_code == 200:
            resp_json = response.json()
            self.access_token = resp_json['access_token']
            self.instance_url = resp_json['instance_url']
            return self.access_token, self.instance_url
        else:
            raise Exception(f"Salesforce Auth failed: {response.text}")

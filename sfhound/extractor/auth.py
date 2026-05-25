
import yaml
import requests
import jwt
import time

VALID_AUTH_TYPES = ('certificate_and_secret', 'client_credential_flow')

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
        auth_type = self.config.get('type', 'certificate_and_secret')
        if auth_type == 'certificate_and_secret':
            return self._authenticate_jwt_certificate()
        elif auth_type == 'client_credential_flow':
            return self._authenticate_client_credentials()
        else:
            raise ValueError(f"Unknown auth type '{auth_type}'. Valid options: {', '.join(VALID_AUTH_TYPES)}")

    def _authenticate_jwt_certificate(self):
        """JWT Bearer flow — requires client_id, username, private_key, and login_url.
        The certificate matching the private key must be uploaded to the Connected App."""
        payload = {
            'iss': self.config['client_id'],
            'sub': self.config['username'],
            'aud': self.config['login_url'],
            'exp': int(time.time()) + 300
        }
        with open(self.config['private_key'], 'r') as key_file:
            private_key = key_file.read()
        assertion = jwt.encode(payload, private_key, algorithm='RS256')
        url = f"{self.config['login_url']}/services/oauth2/token"
        data = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion': assertion
        }
        response = requests.post(url, data=data, timeout=30)
        if response.status_code == 200:
            resp_json = response.json()
            self.access_token = resp_json['access_token']
            self.instance_url = resp_json['instance_url']
            return self.access_token, self.instance_url
        else:
            raise Exception(f"Salesforce Auth (certificate_and_secret) failed: {response.text}")

    def _authenticate_client_credentials(self):
        """OAuth 2.0 Client Credentials flow — requires client_id, client_secret, and login_url.
        The Connected App must have a 'Run As' user configured in its policies."""
        url = f"{self.config['login_url']}/services/oauth2/token"
        data = {
            'grant_type': 'client_credentials',
            'client_id': self.config['client_id'],
            'client_secret': self.config['client_secret'],
        }
        response = requests.post(url, data=data, timeout=30)
        if response.status_code == 200:
            resp_json = response.json()
            self.access_token = resp_json['access_token']
            self.instance_url = resp_json['instance_url']
            return self.access_token, self.instance_url
        else:
            raise Exception(f"Salesforce Auth (client_credential_flow) failed: {response.text}")

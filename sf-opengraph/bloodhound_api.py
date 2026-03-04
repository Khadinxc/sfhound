

import json
import time
import requests
import yaml
import os
import hmac
import hashlib
import base64
from datetime import datetime, timezone

# Job status codes (from BloodHound source)
_JOB_STATUS = {
    -1: "Invalid",
    0:  "Ready",
    1:  "Running",
    2:  "Complete",
    3:  "Canceled",
    4:  "Timed Out",
    5:  "Failed",
    6:  "Ingesting",
    7:  "Analyzing",
    8:  "Partially Complete",
}
_TERMINAL_STATES = {2, 3, 4, 5, 8, -1}
_SUCCESS_STATES  = {2, 8}



class BloodHoundAPI:
        def validate_opengraph_json(self, graph_path):
            from bhopengraph.OpenGraph import OpenGraph as _OpenGraph
            og = _OpenGraph()
            if not og.import_from_file(graph_path):
                print('OpenGraph JSON validation failed: could not parse or load file.')
                return False

            node_count = og.get_node_count()
            edge_count = og.get_edge_count()

            # Check for structural schema errors only; isolated nodes are expected
            # in sfhound graphs (e.g. objects with no permissions yet assigned)
            # and should not block upload.
            _is_valid, _errors = og.validate_graph()
            schema_errors = [e for e in _errors if 'isolated' not in e.lower()]
            if schema_errors:
                print(f'OpenGraph JSON validation failed ({len(schema_errors)} schema error(s)):')
                for err in schema_errors[:20]:
                    print('  -', err)
                if len(schema_errors) > 20:
                    print(f'  ... and {len(schema_errors) - 20} more.')
                return False

            print(f'OpenGraph JSON validation passed ({node_count} nodes, {edge_count} edges).')
            return True
        def __init__(self, config):
            """
            Initialize BloodHound API client.
            
            Args:
                config: Either a dict containing configuration or a path to config YAML file (str)
            """
            if isinstance(config, dict):
                # Config dict passed directly (from CLI + YAML merge)
                parsed_config = config
            elif isinstance(config, str):
                # Config path passed (backward compatibility)
                with open(config, 'r') as f:
                    parsed_config = yaml.safe_load(f)
            else:
                raise ValueError("config must be either a dict or a path to YAML file")
            
            bh_cfg = parsed_config.get('bloodhound', {})
            self.api_key = bh_cfg.get('Key')
            self.api_id = bh_cfg.get('ID')
            self.username = bh_cfg.get('username')
            self.password = bh_cfg.get('password')
            self.url = bh_cfg.get('url', 'http://127.0.0.1:8080')
            self.auto_ingest = bh_cfg.get('auto-ingest', False)
            self.jwt = None
            self.base_url = self.url.rstrip('/') + '/api/v1'
            self.clear_url = self.url.rstrip('/') + '/api/v2/clear-database'
            self.login_url = self.url.rstrip('/') + '/api/v2/login'

        def login(self):
            if self.jwt:
                return self.jwt
            headers = {
                'accept': 'application/json',
                'Content-Type': 'application/json',
                'Prefer': 'wait=30'
            }
            data = {
                "login_method": "secret",
                "username": self.username,
                "secret": self.password
            }
            resp = requests.post(self.login_url, headers=headers, json=data, timeout=10)
            print("Login response status:", resp.status_code)
            print("Login response text:", resp.text)
            if resp.status_code == 200:
                try:
                    result = resp.json()
                    # Extract session_token from data
                    self.jwt = result.get('data', {}).get('session_token')
                except Exception:
                    self.jwt = None
                if self.jwt:
                    print('BloodHound API login successful.')
                    return self.jwt
                else:
                    print('BloodHound API login: No token found in response.')
                    return None
            else:
                print(f'Failed to login to BloodHound API: {resp.status_code} {resp.text}')
                return None

        def _get_signature_headers(self, method, uri, body=b''):
            # RFC3339 to hour
            now = datetime.now(timezone.utc)
            request_date = now.strftime('%Y-%m-%dT%H')
            # Step 1: HMAC-SHA256 with token key
            digester = hmac.new(base64.b64decode(self.api_key), digestmod=hashlib.sha256)
            # Step 2: method+uri
            digester.update((method.upper() + uri).encode('utf-8'))
            # Step 3: date
            digester = hmac.new(digester.digest(), request_date.encode('utf-8'), hashlib.sha256)
            # Step 4: body (if any)
            if body:
                digester = hmac.new(digester.digest(), body, hashlib.sha256)
            else:
                digester = hmac.new(digester.digest(), b'', hashlib.sha256)
            signature = base64.b64encode(digester.digest()).decode('utf-8')
            return {
                'Authorization': f'bhesignature {self.api_id}',
                'RequestDate': now.strftime('%Y-%m-%dT%H:%M:%SZ'),
                'Signature': signature
            }

        def clear_database(self, settle_timeout=60, settle_interval=2):
            jwt = self.login()
            if not jwt:
                print('No JWT token available for BloodHound clear-database endpoint.')
                return
            headers = {
                'accept': 'text/plain',
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {jwt}',
                'Prefer': 'wait=30'
            }
            data = {
                "deleteCollectedGraphData": True,
                "deleteFileIngestHistory": True,
                "deleteDataQualityHistory": True,
                "deleteAssetGroupSelectors": [0]
            }
            resp = requests.post(self.clear_url, headers=headers, json=data)
            if resp.status_code not in (200, 204):
                print(f'Failed to clear BloodHound database: {resp.status_code} {resp.text}')
                return
            print('BloodHound database cleared — waiting for all jobs to settle...')

            # deleteFileIngestHistory cancels active jobs asynchronously.
            # Poll until every job is in a terminal state before returning,
            # so upload_graph() never races against a winding-down job.
            deadline = time.time() + settle_timeout
            while time.time() < deadline:
                r = requests.get(
                    self.url.rstrip('/') + '/api/v2/file-upload',
                    headers={'Authorization': f'Bearer {jwt}'},
                    timeout=10,
                )
                if r.status_code == 200:
                    jobs = r.json().get('data') or []
                    active = [j for j in jobs if j.get('status') not in _TERMINAL_STATES]
                    if not active:
                        print('[+] All jobs settled — BloodHound is ready.')
                        return
                    labels = [_JOB_STATUS.get(j['status'], str(j['status'])) for j in active]
                    print(f'[*] Waiting for {len(active)} job(s) to settle: {", ".join(labels)}')
                time.sleep(settle_interval)

            print(f'[!] Timed out waiting for jobs to settle after {settle_timeout}s — proceeding anyway.')

        def upload_graph(self, graph_path, poll_interval=15, timeout=600):
            if not self.auto_ingest:
                print('BloodHound auto-ingest is disabled in config.')
                return

            jwt = self.login()
            if not jwt:
                print('No JWT token available for BloodHound ingest endpoint.')
                return

            base = self.url.rstrip('/')
            # Shared session with auth header
            s = requests.Session()
            s.headers.update({'Authorization': f'Bearer {jwt}'})

            # ------------------------------------------------------------------
            # Pre-flight: abort if stuck jobs exist
            # ------------------------------------------------------------------
            r = s.get(f'{base}/api/v2/file-upload', timeout=10)
            if r.status_code == 200:
                jobs = r.json().get('data') or []
                stuck = [j for j in jobs if j.get('status') not in _TERMINAL_STATES]
                if stuck:
                    for j in stuck:
                        label = _JOB_STATUS.get(j['status'], str(j['status']))
                        print(f'[!] Stuck job id={j["id"]} status={label}')
                    print('[!] BloodHound has active/stuck jobs — upload aborted.')
                    return

            # ------------------------------------------------------------------
            # Validate schema
            # ------------------------------------------------------------------
            if not self.validate_opengraph_json(graph_path):
                print('Upload aborted due to OpenGraph JSON validation errors.')
                return

            # ------------------------------------------------------------------
            # Step 1: Start upload job
            # ------------------------------------------------------------------
            r = s.post(f'{base}/api/v2/file-upload/start', timeout=10)
            if r.status_code not in (200, 201):
                print(f'Failed to start file upload job: {r.status_code} {r.text}')
                return
            job_id = (r.json().get('id') or
                      (r.json().get('data') or {}).get('id'))
            if not job_id:
                print('No file upload job id returned.')
                return
            print(f'[*] Upload job created: {job_id}')

            # ------------------------------------------------------------------
            # Step 2: Upload file bytes
            # ------------------------------------------------------------------
            file_name = os.path.basename(graph_path)
            print(f'[*] Uploading {file_name} ...')
            with open(graph_path, 'rb') as f:
                file_bytes = f.read()
            upload_headers = {
                'Content-Type': 'application/json',
                'Prefer': 'wait=30',
                'X-File-Upload-Name': file_name,
            }
            r = s.post(f'{base}/api/v2/file-upload/{job_id}',
                       data=file_bytes, headers=upload_headers, timeout=300)
            if r.status_code not in (200, 201, 202):
                print(f'Failed to upload graph: {r.status_code} {r.text}')
                return
            print('[+] File uploaded successfully')

            # ------------------------------------------------------------------
            # Step 3: Verify job is Running, then end it (triggers ingestion)
            # ------------------------------------------------------------------
            r = s.get(f'{base}/api/v2/file-upload',
                      params={'id': f'eq:{job_id}'}, timeout=10)
            if r.status_code == 200:
                jobs = r.json().get('data') or []
                job = next((j for j in jobs if j.get('id') == job_id), None)
                if job:
                    status = job.get('status')
                    if status != 1:  # must be Running
                        label = _JOB_STATUS.get(status, str(status))
                        print(f'[!] Job {job_id} is in state \'{label}\' — expected Running. Aborting.')
                        return

            r = s.post(f'{base}/api/v2/file-upload/{job_id}/end', timeout=30)
            if r.status_code not in (200, 201):
                print(f'Failed to end upload job: {r.status_code} {r.text}')
                return
            print('[+] Ingestion started')

            # ------------------------------------------------------------------
            # Step 4: Poll until terminal state
            # ------------------------------------------------------------------
            print(f'[*] Polling job {job_id} every {poll_interval}s (timeout {timeout}s)...')
            deadline = time.time() + timeout
            while time.time() < deadline:
                r = s.get(f'{base}/api/v2/file-upload',
                          params={'id': f'eq:{job_id}'}, timeout=30)
                if r.status_code != 200:
                    time.sleep(poll_interval)
                    continue
                jobs = r.json().get('data') or []
                job = next((j for j in jobs if j.get('id') == job_id), None)
                if not job:
                    time.sleep(poll_interval)
                    continue
                status  = job.get('status')
                label   = _JOB_STATUS.get(status, f'Unknown({status})')
                total   = job.get('total_files', '?')
                failed  = job.get('failed_files', 0)
                partial = job.get('partial_failed_files', 0)
                msg     = job.get('status_message', '')
                print(f'    [{label}] total={total} failed={failed} partial={partial}'
                      + (f' — {msg}' if msg else ''))
                if status in _TERMINAL_STATES:
                    if status in _SUCCESS_STATES:
                        print(f'[+] Ingestion complete: {label}')
                    else:
                        print(f'[!] Ingestion ended with status: {label}')
                    break
                time.sleep(poll_interval)
            else:
                print(f'[!] Timed out waiting for job {job_id} after {timeout}s')
                return

            # ------------------------------------------------------------------
            # Step 5: Print completed task details
            # ------------------------------------------------------------------
            r = s.get(f'{base}/api/v2/file-upload/{job_id}/completed-tasks', timeout=30)
            if r.status_code == 200:
                tasks = r.json().get('data') or []
                if tasks:
                    print('[+] Completed tasks:')
                    print(json.dumps(tasks, indent=2))
                else:
                    print('[*] No completed task records available')
            else:
                print(f'[!] Could not retrieve completed tasks (HTTP {r.status_code})')

        def cypher_query(self, query: str, include_properties: bool = True):
            """
            Execute a Cypher query against BloodHound API.
            
            Args:
                query: Cypher query string
                include_properties: Whether to include node/edge properties in results
            
            Returns:
                dict: API response data containing 'data' key with query results
            """
            jwt = self.login()
            if not jwt:
                raise Exception("Failed to authenticate with BloodHound API")
            
            url = f"{self.url.rstrip('/')}/api/v2/graphs/cypher"
            headers = {
                'accept': 'application/json',
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {jwt}',
                'Prefer': 'wait=30'
            }
            payload = {
                "query": query,
                "include_properties": include_properties
            }
            
            resp = requests.post(url, headers=headers, json=payload, timeout=60)
            
            if resp.status_code != 200:
                raise Exception(f"Cypher query failed (HTTP {resp.status_code}): {resp.text}")
            
            return resp.json()

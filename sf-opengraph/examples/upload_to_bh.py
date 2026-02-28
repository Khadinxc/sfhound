"""
BloodHound API:
1. Authenticate
2. Create upload job
3. Upload graph file
4. Check upload job status

Usage:
    python upload_to_bh.py [path/to/graph.json]
    
If no file path is provided, will look for kaibersec-org-demo.json in opengraph_output/,
then fall back to the most recent file in opengraph_output/
"""

import json
import argparse
import requests
import sys
import yaml
import os
import glob
import time

CONFIG_PATH = "config.yaml"

# Load configuration
with open(CONFIG_PATH, 'r', encoding="utf-8") as f:
    config = yaml.safe_load(f)['bloodhound']
    BASE_URL = config['url']
    USERNAME = config['username']
    SECRET = config['password']

session = requests.Session()

JOB_STATUS = {
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

TERMINAL_STATES = {2, 3, 4, 5, 8, -1}
SUCCESS_STATES  = {2, 8}


def authenticate():
    print("[*] Authenticating...")

    url = f"{BASE_URL}/api/v2/login"

    payload = {
        "login_method": "secret",
        "username": USERNAME,
        "secret": SECRET
    }

    r = session.post(url, json=payload, timeout=10)

    if r.status_code != 200:
        print("[!] Authentication failed")
        print(r.text)
        sys.exit(1)

    data = r.json()
    
    # Handle nested response structure
    token = (
        data.get("session_token")
        or data.get("token")
        or (data.get("data") or {}).get("session_token")
        or (data.get("data") or {}).get("token")
    )

    if not token:
        print("[!] No JWT returned")
        print(data)
        sys.exit(1)

    session.headers.update({
        "Authorization": f"Bearer {token}"
    })

    print("[+] Authenticated successfully")


def check_for_stuck_jobs():
    """Abort if any jobs are already in a non-terminal state to avoid interference."""
    print("[*] Checking for stuck jobs...")

    r = session.get(f"{BASE_URL}/api/v2/file-upload", timeout=10)
    if r.status_code != 200:
        print(f"[!] Could not check existing jobs (HTTP {r.status_code}) — proceeding anyway")
        return

    jobs = r.json().get("data") or []
    stuck = [j for j in jobs if j.get("status") not in TERMINAL_STATES]

    if stuck:
        for j in stuck:
            label = JOB_STATUS.get(j["status"], f"Unknown({j['status']})")
            print(f"[!] Found stuck job id={j['id']} status={label}")
        print("[!] There are active/stuck jobs. Clear them in BloodHound before uploading.")
        sys.exit(1)

    print("[+] No stuck jobs found")


def create_upload_job():
    print("[*] Creating upload job...")

    r = session.post(f"{BASE_URL}/api/v2/file-upload/start", timeout=10)

    if r.status_code not in [200, 201]:
        print(f"[!] Failed to create upload job (HTTP {r.status_code})")
        print(r.text)
        sys.exit(1)

    data = r.json()
    job_id = data.get("id") or (data.get("data") or {}).get("id")

    if not job_id:
        print("[!] No job ID returned")
        print(data)
        sys.exit(1)

    # Verify the job is in Ready state (0) before proceeding
    r2 = session.get(f"{BASE_URL}/api/v2/file-upload", params={"id": f"eq:{job_id}"}, timeout=10)
    if r2.status_code == 200:
        jobs = r2.json().get("data") or []
        job = next((j for j in jobs if j.get("id") == job_id), None)
        if job and job.get("status") not in (0, 1):  # Ready or Running both OK at start
            label = JOB_STATUS.get(job["status"], str(job["status"]))
            print(f"[!] Job {job_id} is in unexpected state: {label}")
            sys.exit(1)

    print(f"[+] Upload job created: {job_id}")
    return job_id


def upload_file(job_id, file_path):
    file_name = os.path.basename(file_path)
    print(f"[*] Uploading file: {file_path}")
    print("[*] This may take several minutes for large graphs...")

    url = f"{BASE_URL}/api/v2/file-upload/{job_id}"

    with open(file_path, "rb") as f:
        data = f.read()

    headers = {
        "Content-Type": "application/json",
        "Prefer": "wait=30",
        "X-File-Upload-Name": file_name,
    }

    # Increase timeout for large graph ingestion (5 minutes)
    r = session.post(url, data=data, headers=headers, timeout=300)

    if r.status_code not in [200, 201, 202]:
        print(f"[!] Upload failed (HTTP {r.status_code})")
        print(r.text)
        sys.exit(1)

    print("[+] File uploaded successfully")


def end_upload_job(job_id):
    """Signal BloodHound to begin processing the uploaded file(s)."""
    print(f"[*] Ending upload job {job_id} (triggers ingestion)...")

    # Verify the job is still in Running state before ending
    r = session.get(f"{BASE_URL}/api/v2/file-upload", params={"id": f"eq:{job_id}"}, timeout=10)
    if r.status_code == 200:
        jobs = r.json().get("data") or []
        job = next((j for j in jobs if j.get("id") == job_id), None)
        if job:
            status = job.get("status")
            if status != 1:  # Must be Running
                label = JOB_STATUS.get(status, str(status))
                print(f"[!] Job {job_id} is in state '{label}' — expected Running. Cannot end.")
                sys.exit(1)

    r = session.post(f"{BASE_URL}/api/v2/file-upload/{job_id}/end", timeout=30)

    if r.status_code not in [200, 201]:
        print(f"[!] Failed to end upload job (HTTP {r.status_code})")
        print(r.text)
        sys.exit(1)

    print("[+] Upload job ended — ingestion started")


def check_upload_status(job_id, poll_interval=15, timeout=600):
    """Poll the job status until terminal, then print completed task details."""
    print(f"[*] Polling job {job_id} every {poll_interval}s (timeout {timeout}s)...")

    job_url   = f"{BASE_URL}/api/v2/file-upload"
    tasks_url = f"{BASE_URL}/api/v2/file-upload/{job_id}/completed-tasks"
    deadline  = time.time() + timeout

    while time.time() < deadline:
        r = session.get(job_url, params={"id": f"eq:{job_id}"}, timeout=30)
        if r.status_code != 200:
            print(f"[!] Failed to poll job status (HTTP {r.status_code}): {r.text}")
            time.sleep(poll_interval)
            continue

        jobs = r.json().get("data") or []
        job = next((j for j in jobs if j.get("id") == job_id), None)
        if not job:
            print(f"[!] Job {job_id} not found in list response")
            time.sleep(poll_interval)
            continue
        status  = job.get("status")
        label   = JOB_STATUS.get(status, f"Unknown({status})")
        total   = job.get("total_files", "?")
        failed  = job.get("failed_files", 0)
        partial = job.get("partial_failed_files", 0)
        msg     = job.get("status_message", "")

        print(f"    [{label}] total={total} failed={failed} partial={partial}" +
              (f" — {msg}" if msg else ""))

        if status in TERMINAL_STATES:
            if status in SUCCESS_STATES:
                print(f"[+] Ingestion finished: {label}")
            else:
                print(f"[!] Ingestion ended with status: {label}")
            break

        time.sleep(poll_interval)
    else:
        print(f"[!] Timed out waiting for job {job_id} after {timeout}s")

    # Print completed task details
    r = session.get(tasks_url, timeout=30)
    if r.status_code == 200:
        tasks = r.json().get("data") or []
        if tasks:
            print("[+] Completed tasks:")
            print(json.dumps(tasks, indent=2))
        else:
            print("[*] No completed task records available")
    else:
        print(f"[!] Could not retrieve completed tasks (HTTP {r.status_code})")


def get_most_recent_graph():
    """Find kaibersec-org-demo.json or the most recent graph file in opengraph_output/"""
    output_dir = "./opengraph_output"

    # Prefer kaibersec-org-demo.json if present
    demo_file = os.path.join(output_dir, "kaibersec-org-demo.json")
    if os.path.exists(demo_file):
        return demo_file

    files = glob.glob(f"{output_dir}/*.json")

    if not files:
        print("[!] No graph files found in opengraph_output/")
        sys.exit(1)

    # Get most recent file
    latest_file = max(files, key=os.path.getctime)
    return latest_file


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Upload an OpenGraph JSON file to BloodHound CE and wait for ingestion to complete.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python upload_to_bh.py                          # auto-select most recent file\n"
            "  python upload_to_bh.py opengraph_output/my.json # upload a specific file\n"
        ),
    )
    parser.add_argument(
        "file",
        nargs="?",
        metavar="FILE",
        help="Path to the graph JSON file to upload. "
             "Defaults to kaibersec-org-demo.json if present, otherwise the most recent file in opengraph_output/.",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=15,
        metavar="SECONDS",
        help="How often (in seconds) to poll ingestion status (default: 15).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        metavar="SECONDS",
        help="Maximum seconds to wait for ingestion to complete (default: 600).",
    )
    args = parser.parse_args()

    if args.file:
        FILE_PATH = args.file
    else:
        FILE_PATH = get_most_recent_graph()
        print(f"[*] No file specified, using: {FILE_PATH}")

    if not os.path.exists(FILE_PATH):
        print(f"[!] File not found: {FILE_PATH}")
        sys.exit(1)

    authenticate()
    check_for_stuck_jobs()
    job_id = create_upload_job()
    upload_file(job_id, FILE_PATH)
    end_upload_job(job_id)
    check_upload_status(job_id, poll_interval=args.poll_interval, timeout=args.timeout)
    print("[✓] Done")
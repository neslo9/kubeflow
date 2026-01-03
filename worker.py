#!/usr/bin/env python3
import os
import json
import time
import subprocess
import requests
import redis
import socket
import re
from datetime import datetime, timezone
from typing import Optional, List

# Konfiguracja
REDIS_URL = os.getenv("REDIS_URL", "redis://192.168.1.101:30079/0")
BACKEND_URL = os.getenv("BACKEND_URL", "http://dashboard.app.kubeflow.masternode:30008")
PLAYBOOK_PATH = os.getenv("PLAYBOOK_PATH", "/usr/local/bin/dockerflow_config/playbooks/test/main-dbless.yml")
ACCEPT_PLAYBOOK_PATH = os.getenv("ACCEPT_PLAYBOOK_PATH", "/usr/local/bin/dockerflow_config/playbooks/test/tag_and_push.yml")
LOG_DIR = os.getenv("LOG_DIR")

# Token workera (wartość jawna, nie base64)
WORKER_TOKEN = os.getenv("WORKER_TOKEN")

if not WORKER_TOKEN:
    print("ERROR: WORKER_TOKEN not set. Set environment variable WORKER_TOKEN before running the worker.")
    raise SystemExit(1)

os.makedirs(LOG_DIR, exist_ok=True)

r = redis.Redis.from_url(REDIS_URL, decode_responses=True)


def now_iso():
    """Helper used ONLY for JSON payloads, not for console logging."""
    return datetime.now(timezone.utc).isoformat()


def headers_with_auth():
    """Zwraca nagłówki z Authorization Bearer tokenem dla requestów do backendu."""
    return {"Authorization": f"Bearer {WORKER_TOKEN}"}


def load_summaries_file(deploy_id):
    """Wczytuje summaries_{deploy_id}.json i normalizuje wynik do listy summary dictów."""
    path = os.path.join(LOG_DIR, f"summaries_{deploy_id}.json")
    if not os.path.exists(path):
        print(f"Summaries file not found: {path}")
        return []

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            data = json.load(fh)
    except Exception as e:
        print(f"Error loading summaries JSON {path}: {e}")
        return []

    if isinstance(data, dict):
        items = []
        for name, val in data.items():
            items.append({
                "name": name,
                "build_status": (val.get("build_status") or val.get("build") or "unknown").lower(),
                "status": (val.get("status") or val.get("deploy") or "unknown").lower(),
                "security_checks": val.get("security_checks", {}) or {},
                "issues": val.get("issues", []) or [],
                "critical_vulns": int(val.get("critical_vulns", 0)),
                "high_vulns": int(val.get("high_vulns", 0)),
                "image_tag": val.get("image_tag", "latest"),
                "backup_tag": val.get("backup_tag")
            })
        print(f"Loaded summaries from JSON file (dict) : {path}")
        return items
    elif isinstance(data, list):
        normalized = []
        for item in data:
            normalized.append({
                "name": item.get("name"),
                "build_status": (item.get("build_status") or "unknown").lower(),
                "status": (item.get("status") or "unknown").lower(),
                "security_checks": item.get("security_checks", {}) or {},
                "issues": item.get("issues", []) or [],
                "critical_vulns": int(item.get("critical_vulns", 0)),
                "high_vulns": int(item.get("high_vulns", 0)),
                "image_tag": item.get("image_tag", "latest"),
                "backup_tag": item.get("backup_tag")
            })
        print(f"Loaded summaries from JSON file (list): {path}")
        return normalized
    else:
        print(f"Unexpected JSON format in {path}, expected dict or list.")
        return []


def parse_summaries_from_log(log_file_path):
    """Fallback parser - parsuje log playbooka do listy summary dictów."""
    summaries = []
    if not os.path.exists(log_file_path):
        return summaries

    service_name = None
    build_status = None
    deploy_status = None
    security_checks = None
    critical_vulns = None
    high_vulns = None

    header_re = re.compile(r"^=== Service:\s+(?P<name>.+?)\s+===$")
    build_re = re.compile(r"^Build:\s+(?P<val>\w+)")
    deploy_re = re.compile(r"^Deploy:\s+(?P<val>\w+)")
    checks_re = re.compile(r"^Checks:\s+(?P<val>.+)$")
    vulns_re = re.compile(r"^Vulns:\s+critical=(?P<critical>\d+),\s+high=(?P<high>\d+)")

    def flush_block():
        nonlocal service_name, build_status, deploy_status, security_checks, critical_vulns, high_vulns
        if service_name is None:
            return
        summaries.append({
            "name": service_name,
            "build_status": (build_status or "unknown").lower(),
            "status": (deploy_status or "unknown").lower(),
            "security_checks": security_checks if isinstance(security_checks, dict) else {},
            "issues": [],
            "critical_vulns": int(critical_vulns) if critical_vulns is not None else 0,
            "high_vulns": int(high_vulns) if high_vulns is not None else 0,
            "image_tag": "latest",
            "backup_tag": None
        })
        service_name = build_status = deploy_status = security_checks = critical_vulns = high_vulns = None

    try:
        with open(log_file_path, "r", encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue
                m = header_re.match(line)
                if m:
                    flush_block()
                    service_name = m.group("name")
                    continue
                m = build_re.match(line)
                if m:
                    build_status = m.group("val")
                    continue
                m = deploy_re.match(line)
                if m:
                    deploy_status = m.group("val")
                    continue
                m = checks_re.match(line)
                if m:
                    try:
                        security_checks = json.loads(m.group("val"))
                    except Exception:
                        security_checks = {}
                    continue
                m = vulns_re.match(line)
                if m:
                    critical_vulns = m.group("critical")
                    high_vulns = m.group("high")
                    continue
            flush_block()
    except Exception as e:
        print(f"Error parsing playbook log {log_file_path}: {e}")

    return summaries

def load_pod_logs(deploy_id: int) -> Optional[str]:
    pod_log_file = f"/var/log/kubeflow/k8s_logs_{deploy_id}.json"
    try:
        if os.path.exists(pod_log_file):
            with open(pod_log_file, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            k8s_logs = data.get("k8s_logs")
            if isinstance(k8s_logs, (list, dict)):
                return json.dumps(k8s_logs, ensure_ascii=False)
            return str(k8s_logs) if k8s_logs is not None else None
        return None
    except Exception as e:
        return f"Error reading pod logs: {e}"

def run_playbook(job):
    image_deploy_id = job.get("image_deploy_id") or job.get("deploy_id")
    repo_name = job.get("repo_name")
    project = job.get("project")
    current_worker = socket.gethostname()
    # Log filenames still need timestamp
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    log_file = os.path.join(LOG_DIR, f"{project}_{repo_name}_{image_deploy_id}_playbook.log")

    print(f"Running playbook for {project}/{repo_name} (image_deploy_id={image_deploy_id})")
    print(f"Job payload: {job}")

    env = os.environ.copy()
    env.update({
        "ANSIBLE_STDOUT_CALLBACK": "default",
        "ANSIBLE_HOST_KEY_CHECKING": "False"
    })
    
    # Ensure backend_token is passed if needed, currently reading from env inside script but passed as arg too
    backend_token_arg = os.getenv("WORKER_TOKEN", "")

    cmd = [
        "ansible-playbook",
        PLAYBOOK_PATH,
        "-e", f"repo_name={repo_name}",
        "-e", f"project={project}",
        "-e", f"deploy_id={image_deploy_id}",
        "-e", f"backend_token={backend_token_arg}",
        "-vv"
    ]

    try:
        with open(log_file, "w", encoding="utf-8", errors="ignore") as f:
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, env=env)
            retcode = result.returncode
    except Exception as e:
        print(f"Error running playbook command: {e}")
        retcode = 2

    status = "success" if retcode == 0 else "failed"
    print(f"Playbook finished with status: {status}, log: {log_file}")

    summaries = load_summaries_file(image_deploy_id)
    if not summaries:
        summaries = parse_summaries_from_log(log_file)

    payload = {
        "status": "success" if status == "success" else "failed",
        "timestamp": now_iso(),
        "log_file": log_file,
        "summaries": summaries,
        "worker": current_worker
    }

    print(f"Sending payload to backend for image_deploy_id={image_deploy_id}")
    try:
        url = f"{BACKEND_URL}/images/{image_deploy_id}/complete"
        resp = requests.post(url, json=payload, headers=headers_with_auth(), timeout=30)
        print(f"Backend response: {resp.status_code} {getattr(resp, 'text', '')}")
    except Exception as e:
        print(f"Error updating backend: {e}")

    # -------------------------
    # Failed logs handling
    # -------------------------
    if status != "success" or not summaries:
        print(f"Deploy failed or missing summaries -> preparing failed logs payload")

        whole_log_ctx = ""
        try:
            if os.path.exists(log_file):
                with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                    whole_log_ctx = f.read()
        except Exception:
            whole_log_ctx = ""

        failed_task_info = "unknown task"
        last_playbook_lines = ""

        task_re = re.compile(r"^TASK \[(?P<task>.+?)\]", re.MULTILINE)
        fatal_re = re.compile(r"fatal: .*FAILED!", re.IGNORECASE)

        matches = list(task_re.finditer(whole_log_ctx))
        if matches:
            for m in reversed(matches):
                task_start = m.start()
                next_task_start = len(whole_log_ctx)
                idx = matches.index(m)
                if idx + 1 < len(matches):
                    next_task_start = matches[idx + 1].start()
                task_block = whole_log_ctx[task_start:next_task_start]
                if fatal_re.search(task_block):
                    failed_task_info = f"TASK [{m.group('task')}]"
                    fatal_lines = [l for l in task_block.splitlines() if fatal_re.search(l)]
                    if fatal_lines:
                        last_playbook_lines = fatal_lines[-1].strip()
                    else:
                        last_playbook_lines = task_block[-200:]
                    break

        if not last_playbook_lines:
            last_playbook_lines = whole_log_ctx[-200:]

        pod_log_lines = load_pod_logs(image_deploy_id)

        failed_payload = {
            "failed_task_info": failed_task_info,
            "last_playbook_lines": last_playbook_lines,
            "pod_log_lines": pod_log_lines,
        }

        try:
            url = f"{BACKEND_URL}/image_test_pipeline/{image_deploy_id}/update-logs"
            resp = requests.post(url, json=failed_payload, headers=headers_with_auth(), timeout=30)
            print(f"/update-logs backend response: {resp.status_code} {getattr(resp, 'text', '')}")
        except Exception as e:
            print(f"Error sending failed logs to backend: {e}")

def run_accept(job):
    image_details_id = job.get("image_details_id")
    project = job.get("project")
    service_name = job.get("repo_name")
    target_image = job.get("target_image") or job.get("image_name") or job.get("image_name_tag")
    service_tag = job.get("image_tag")
    new_tag = job.get("new_tag", "")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    log_file = os.path.join(LOG_DIR, f"{project}_{service_name}_{timestamp}_accept.log")
    tag_output_file = os.path.join(LOG_DIR, f"{project}_{service_name}_{timestamp}_tag.txt")

    print(f"Accept job for {project}/{service_name} (id={image_details_id})")
    print(f"Job payload: {job}")

    env = os.environ.copy()
    env.update({
        "ANSIBLE_STDOUT_CALLBACK": "default",
        "ANSIBLE_HOST_KEY_CHECKING": "False"
    })
    harbor_url_val = os.getenv("HARBOR_URL", "harbor.app.kubeflow.masternode:30002")
    cmd = [
        "ansible-playbook",
        ACCEPT_PLAYBOOK_PATH,
        "-e", f"project={project}",
        "-e", f"service_name={service_name}",
        "-e", f"target_image={target_image}",
        "-e", f"service_tag={service_tag}",
        "-e", f"new_tag={new_tag}",
        "-e", f"output_file={tag_output_file}",
        "-e", f"harbor_url='{harbor_url_val}'",
        "-vv"
    ]

    try:
        with open(log_file, "w", encoding="utf-8", errors="ignore") as f:
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, env=env)
            result_code = result.returncode
    except Exception as e:
        print(f"Error running accept playbook: {e}")
        result_code = 2

    tag = None
    success = False
    if result_code == 0 and os.path.exists(tag_output_file):
        try:
            with open(tag_output_file, "r", encoding="utf-8", errors="ignore") as tf:
                tag = tf.read().strip()
            success = bool(tag)
        except Exception as e:
            print(f"Error reading tag file: {e}")
            success = False
    else:
        print(f"Playbook failed or tag file missing (rc={result_code})")

    print(f"Accept playbook returncode: {result_code}")

    payload = {
        "image_details_id": image_details_id,
        "tag": tag,
        "success": success
    }

    print(f"Sending accept payload for image_details_id={image_details_id}: {payload}")
    try:
        url = f"{BACKEND_URL}/images/accept/complete/{image_details_id}"
        response = requests.post(url, json=payload, headers=headers_with_auth(), timeout=30)
        print(f"Backend response: {response.status_code} {getattr(response, 'text', '')}")
    except Exception as e:
        print(f"Error reporting accept status: {e}")

# === [NEW SECTION] pods_deployment_queue support ===

def run_pods_deploy(job):
    deploy_id = job.get("deploy_id")
    project = job.get("project")
    repo_name = job.get("repo_name")
    tag = job.get("tag", "latest")
    hosts = [h.strip() for h in job.get("hosts", []) if h and h.strip()]
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    log_file = os.path.join(LOG_DIR, f"{project}_{repo_name}_{timestamp}_pods_deploy.log")

    print(f"[pods_deploy] Start deploy for {project}/{repo_name}, tag={tag}, hosts={hosts}")

    inventory_file = os.getenv("INVENTORY_FILE", "/etc/ansible/hosts")
    playbook_path = os.getenv("PODS_DEPLOY_PLAYBOOK", "/usr/local/bin/kube/playbooks/deploy_on_node.yml")

    if not os.path.exists(playbook_path):
        msg = f"Playbook not found: {playbook_path}"
        print(f"[pods_deploy] {msg}")
        payload = {"deployment_id": deploy_id, "project": project, "repo_name": repo_name, "hosts": hosts, "tag": tag, "success": False, "reason": msg}
        try:
            requests.post(f"{BACKEND_URL}/deploy/complete/{deploy_id}", json=payload, headers=headers_with_auth(), timeout=10)
        except Exception as _:
            pass
        return

    if not os.path.exists(inventory_file):
        msg = f"Inventory not found: {inventory_file}"
        print(f"[pods_deploy] {msg}")
        payload = {"deployment_id": deploy_id, "project": project, "repo_name": repo_name, "hosts": hosts, "tag": tag, "success": False, "reason": msg}
        try:
            requests.post(f"{BACKEND_URL}/deploy/complete/{deploy_id}", json=payload, headers=headers_with_auth(), timeout=10)
        except Exception:
            pass
        return

    cmd = ["ansible-playbook", "-i", inventory_file, playbook_path]
    if hosts:
        limit_hosts = ",".join(hosts)
        cmd += ["--limit", limit_hosts]
    cmd += ["-e", f"project={project}", "-e", f"repo_name={repo_name}", "-e", f"tag={tag}", "-vvv"]

    env = os.environ.copy()
    env.update({
        "ANSIBLE_STDOUT_CALLBACK": "default",
        "ANSIBLE_HOST_KEY_CHECKING": "False"
    })

    print(f"[pods_deploy] CMD: {' '.join(cmd)}")
    try:
        with open(log_file, "w", encoding="utf-8", errors="ignore") as f:
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, env=env)
            rc = result.returncode
    except Exception as e:
        rc = 2
        print(f"[pods_deploy] Error running pods deploy: {e}")

    log_snippet = ""
    try:
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.splitlines()
            log_snippet = "\n".join(lines[-200:])
    except Exception as e:
        content = ""
        print(f"[pods_deploy] Could not read log file: {e}")

    reason = None
    success = (rc == 0)

    if rc == 0:
        if ("No hosts matched" in content) or ("skipping: no hosts matched" in content) or ("PLAY [" not in content):
            success = False
            reason = "no hosts matched / nothing executed"
    else:
        if "UNREACHABLE!" in content or "FAILED!" in content:
            reason = "hosts unreachable or tasks failed"
        else:
            reason = f"ansible return code {rc}"

    payload = {
        "deployment_id": deploy_id,
        "project": project,
        "repo_name": repo_name,
        "hosts": hosts,
        "tag": tag,
        "success": success,
        "log_file": log_file,
        "timestamp": now_iso(),
        "reason": reason,
        "log_snippet": log_snippet
    }

    try:
        url = f"{BACKEND_URL}/deploy/complete/{deploy_id}"
        print(f"[pods_deploy] Sending callback to {url} (success={success})")
        resp = requests.post(url, json=payload, headers=headers_with_auth(), timeout=30)
        print(f"[pods_deploy] Backend response: {resp.status_code} {getattr(resp, 'text', '')}")
    except Exception as e:
        print(f"[pods_deploy] Error sending callback: {e}")

def main():
    my_hostname = socket.gethostname()
    print(f"Worker started on: {my_hostname}")

    queues_to_watch = [
        f"image_accept_queue:{my_hostname}",
        f"pods_deployment_queue:{my_hostname}",
        "image_test_queue"
    ]

    print(f"Listening on: {queues_to_watch}")

    while True:
        try:
            popped = r.brpop(queues_to_watch, timeout=5)
            if not popped:
                continue

            full_queue_name, job_json = popped

            if isinstance(full_queue_name, bytes):
                full_queue_name = full_queue_name.decode('utf-8')

            try:
                job = json.loads(job_json)
            except Exception:
                print(f"Invalid JSON in {full_queue_name}")
                continue

            if full_queue_name == "image_test_queue":
                run_playbook(job)
            elif full_queue_name.startswith("image_accept_queue"):
                run_accept(job)
            elif full_queue_name.startswith("pods_deployment_queue"):
                run_pods_deploy(job)
            else:
                print(f"Unknown queue type: {full_queue_name}")

        except Exception as e:
            print(f"Worker critical error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()

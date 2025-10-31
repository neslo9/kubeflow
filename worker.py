#!/usr/bin/env python3
import os
import json
import time
import subprocess
import requests
import redis
from datetime import datetime, timezone

# Konfiguracja
REDIS_URL = os.getenv("REDIS_URL", "redis://192.168.1.101:30079/0")
BACKEND_URL = os.getenv("BACKEND_URL", "http://dashboard.app.kubeflow.masternode:30008")
PLAYBOOK_PATH = os.getenv("PLAYBOOK_PATH", "/usr/local/bin/dockerflow_config/playbooks/test/main-dbless.yml")
ACCEPT_PLAYBOOK_PATH = os.getenv("ACCEPT_PLAYBOOK_PATH", "/usr/local/bin/dockerflow_config/playbooks/test/tag_and_push.yml")
LOG_DIR = os.getenv("LOG_DIR", "/var/log/dockerflow")

# Token workera (wartość jawna, nie base64)
WORKER_TOKEN = os.getenv("WORKER_TOKEN")

if not WORKER_TOKEN:
    # Szybkie zabezpieczenie - nie startujemy bez tokena
    print("ERROR: WORKER_TOKEN not set. Set environment variable WORKER_TOKEN before running the worker.")
    print("Example: export WORKER_TOKEN='eyJ...'; python worker.py")
    raise SystemExit(1)

os.makedirs(LOG_DIR, exist_ok=True)

r = redis.Redis.from_url(REDIS_URL, decode_responses=True)


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def headers_with_auth():
    """Zwraca nagłówki z Authorization Bearer tokenem dla requestów do backendu."""
    return {"Authorization": f"Bearer {WORKER_TOKEN}"}


def load_summaries_file(deploy_id):
    """Wczytuje summaries_{deploy_id}.json i normalizuje wynik do listy summary dictów."""
    path = os.path.join(LOG_DIR, f"summaries_{deploy_id}.json")
    if not os.path.exists(path):
        print(f"[{now_iso()}] Summaries file not found: {path}")
        return []

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            data = json.load(fh)
    except Exception as e:
        print(f"[{now_iso()}] Error loading summaries JSON {path}: {e}")
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
        print(f"[{now_iso()}] Loaded summaries from JSON file (dict) : {path}")
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
        print(f"[{now_iso()}] Loaded summaries from JSON file (list): {path}")
        return normalized
    else:
        print(f"[{now_iso()}] Unexpected JSON format in {path}, expected dict or list.")
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

    import re
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
        print(f"[{now_iso()}] Error parsing playbook log {log_file_path}: {e}")

    return summaries


def run_playbook(job):
    image_deploy_id = job.get("image_deploy_id") or job.get("deploy_id")
    repo_name = job.get("repo_name")
    project = job.get("project")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    log_file = os.path.join(LOG_DIR, f"{project}_{repo_name}_{image_deploy_id}_playbook.log")

    print(f"[{now_iso()}] Running playbook for {project}/{repo_name} (image_deploy_id={image_deploy_id})")
    print(f"[{now_iso()}] Job payload: {job}")

    env = os.environ.copy()
    env.update({
        "ANSIBLE_STDOUT_CALLBACK": "default",
        "ANSIBLE_HOST_KEY_CHECKING": "False"
    })

    cmd = [
        "ansible-playbook",
        PLAYBOOK_PATH,
        "-e", f"repo_name={repo_name}",
        "-e", f"project={project}",
        "-e", f"deploy_id={image_deploy_id}",
        "-vv"
    ]

    try:
        with open(log_file, "w", encoding="utf-8", errors="ignore") as f:
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, env=env)
            retcode = result.returncode
    except Exception as e:
        print(f"[{now_iso()}] Error running playbook command: {e}")
        retcode = 2

    status = "success" if retcode == 0 else "failed"
    print(f"[{now_iso()}] Playbook finished with status: {status}, log: {log_file}")

    summaries = load_summaries_file(image_deploy_id)
    if not summaries:
        summaries = parse_summaries_from_log(log_file)

    payload = {
        "status": "success" if status == "success" else "failed",
        "timestamp": now_iso(),
        "log_file": log_file,
        "summaries": summaries,
    }

    print(f"[{now_iso()}] Sending payload to backend for image_deploy_id={image_deploy_id}")
    try:
        url = f"{BACKEND_URL}/images/{image_deploy_id}/complete"
        resp = requests.post(url, json=payload, headers=headers_with_auth(), timeout=30)
        print(f"[{now_iso()}] Backend response: {resp.status_code} {getattr(resp, 'text', '')}")
    except Exception as e:
        print(f"[{now_iso()}] Error updating backend: {e}")


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

    print(f"[{now_iso()}] Accept job for {project}/{service_name} (id={image_details_id})")
    print(f"[{now_iso()}] Job payload: {job}")

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
        print(f"[{now_iso()}] Error running accept playbook: {e}")
        result_code = 2

    tag = None
    success = False
    if result_code == 0 and os.path.exists(tag_output_file):
        try:
            with open(tag_output_file, "r", encoding="utf-8", errors="ignore") as tf:
                tag = tf.read().strip()
            success = bool(tag)
        except Exception as e:
            print(f"[{now_iso()}] Error reading tag file: {e}")
            success = False
    else:
        print(f"[{now_iso()}] Playbook failed or tag file missing (rc={result_code})")

    print(f"[{now_iso()}] Accept playbook returncode: {result_code}")

    # Kompatybilny URL z FastAPI endpointem /accept/complete/{image_details_id}
    payload = {
        "image_details_id": image_details_id,
        "tag": tag,
        "success": success
    }

    print(f"[{now_iso()}] Sending accept payload for image_details_id={image_details_id}: {payload}")
    try:
        url = f"{BACKEND_URL}/images/accept/complete/{image_details_id}"
        response = requests.post(url, json=payload, headers=headers_with_auth(), timeout=30)
        print(f"[{now_iso()}] Backend response: {response.status_code} {getattr(response, 'text', '')}")
    except Exception as e:
        print(f"[{now_iso()}] Error reporting accept status: {e}")

# === [NEW SECTION] pods_deployment_queue support ===

def run_pods_deploy(job):
    """
    Obsługa kolejki pods_deployment_queue — deploy podów na wskazanych nodach.
    Uwaga: ta wersja:
     - filtruje puste hosty,
     - sprawdza inventory i playbook,
     - loguje pełne polecenie i fragment logu,
     - wykrywa przypadki "no hosts matched" / brak PLAY w logu.
    """
    deploy_id = job.get("deploy_id")
    project = job.get("project")
    repo_name = job.get("repo_name")
    tag = job.get("tag", "latest")
    # filtrowanie pustych wpisów
    hosts = [h.strip() for h in job.get("hosts", []) if h and h.strip()]
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    log_file = os.path.join(LOG_DIR, f"{project}_{repo_name}_{timestamp}_pods_deploy.log")

    print(f"[{now_iso()}] [pods_deploy] Start deploy for {project}/{repo_name}, tag={tag}, hosts={hosts}")

    inventory_file = os.getenv("INVENTORY_FILE", "/etc/ansible/hosts")
    playbook_path = os.getenv("PODS_DEPLOY_PLAYBOOK", "/usr/local/bin/dockerflow_config/playbooks/test/deploy_on_node.yml")

    # weryfikacja plików
    if not os.path.exists(playbook_path):
        msg = f"Playbook not found: {playbook_path}"
        print(f"[{now_iso()}] [pods_deploy] {msg}")
        payload = {"deployment_id": deploy_id, "project": project, "repo_name": repo_name, "hosts": hosts, "tag": tag, "success": False, "reason": msg}
        try:
            requests.post(f"{BACKEND_URL}/deploy/complete/{deploy_id}", json=payload, headers=headers_with_auth(), timeout=10)
        except Exception as _:
            pass
        return

    if not os.path.exists(inventory_file):
        msg = f"Inventory not found: {inventory_file}"
        print(f"[{now_iso()}] [pods_deploy] {msg}")
        payload = {"deployment_id": deploy_id, "project": project, "repo_name": repo_name, "hosts": hosts, "tag": tag, "success": False, "reason": msg}
        try:
            requests.post(f"{BACKEND_URL}/deploy/complete/{deploy_id}", json=payload, headers=headers_with_auth(), timeout=10)
        except Exception:
            pass
        return

    # przygotowanie polecenia
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

    # logujemy polecenie
    print(f"[{now_iso()}] [pods_deploy] CMD: {' '.join(cmd)}")
    try:
        with open(log_file, "w", encoding="utf-8", errors="ignore") as f:
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, env=env)
            rc = result.returncode
    except Exception as e:
        rc = 2
        print(f"[{now_iso()}] [pods_deploy] Error running pods deploy: {e}")

    # odczyt fragmentu logu dla szybkiego podglądu
    log_snippet = ""
    try:
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.splitlines()
            log_snippet = "\n".join(lines[-200:])  # ostatnie 200 linii
    except Exception as e:
        content = ""
        print(f"[{now_iso()}] [pods_deploy] Could not read log file: {e}")

    # heurystyka: Ansible może zwrócić rc=0 ale nie wykonać nic (np. "No hosts matched")
    reason = None
    success = (rc == 0)

    if rc == 0:
        if ("No hosts matched" in content) or ("skipping: no hosts matched" in content) or ("PLAY [" not in content):
            success = False
            reason = "no hosts matched / nothing executed"
    else:
        # szukamy konkretnych błędów
        if "UNREACHABLE!" in content or "FAILED!" in content:
            reason = "hosts unreachable or tasks failed"
        else:
            reason = f"ansible return code {rc}"

    # payload do backendu z fragmentem logu i powodem
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
        print(f"[{now_iso()}] [pods_deploy] Sending callback to {url} (success={success})")
        resp = requests.post(url, json=payload, headers=headers_with_auth(), timeout=30)
        print(f"[{now_iso()}] [pods_deploy] Backend response: {resp.status_code} {getattr(resp, 'text', '')}")
    except Exception as e:
        print(f"[{now_iso()}] [pods_deploy] Error sending callback: {e}")

def main():
    print(f"[{now_iso()}] Worker started, listening on Redis queues")
    queues = ["image_test_queue", "image_accept_queue", "pods_deployment_queue"]

    while True:
        try:
            popped = r.brpop(queues, timeout=5)
            if not popped:
                continue
            queue_name, job_json = popped
            try:
                job = json.loads(job_json)
            except Exception:
                print(f"[{now_iso()}] Invalid job JSON from {queue_name}: {job_json}")
                continue

            if queue_name == "image_test_queue":
                run_playbook(job)
            elif queue_name == "image_accept_queue":
                run_accept(job)
            elif queue_name == "pods_deployment_queue":
                run_pods_deploy(job)
            else:
                print(f"[{now_iso()}] Unknown queue {queue_name}")

        except Exception as e:
            print(f"[{now_iso()}] Worker error: {e}")
            time.sleep(5)


if __name__ == "__main__":
    main()

#!/home/kavi/malicious_task_detector/venv/bin/python3
"""
TASKGUARD — Splunk Alert Script for Sysmon EventCode 1
Triggered by Splunk real-time alert on every new Sysmon Process Create event.

Flow:
  Sysmon EventCode 1 → Splunk indexes event
  → Real-time alert fires → this script runs
  → Reads gzipped CSV from argv[8]
  → Extracts Sysmon fields (CommandLine, Image, ParentImage, etc.)
  → Calls Flask API on localhost:5000/predict
  → Writes taskguard_* result back to Splunk via HEC (port 8088)
"""

import sys
import json
import csv
import gzip
import requests
import logging
from datetime import datetime, timezone

# ── Configuration ──────────────────────────────────────────
FLASK_URL  = "http://localhost:5000/predict"
HEC_URL    = "http://localhost:8088/services/collector/event"
HEC_TOKEN  = "240099dc-36e5-42f4-8449-e15bb2e5ec0a"
LOG_FILE   = "/home/kavi/malicious_task_detector/taskguard.log"

# ── Logging ────────────────────────────────────────────────
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
log = logging.getLogger('taskguard-splunk')

# ──────────────────────────────────────────────────────────
# HEC SENDER
# ──────────────────────────────────────────────────────────

def send_to_hec(event_data: dict):
    """Write prediction result back into Splunk via HEC."""
    headers = {
        "Authorization": f"Splunk {HEC_TOKEN}",
        "Content-Type" : "application/json"
    }
    payload = {
        "sourcetype" : "ml_prediction",
        "index"      : "main",
        "event"      : event_data
    }
    try:
        r = requests.post(
            HEC_URL,
            headers=headers,
            json=payload,
            verify=False,
            timeout=5
        )
        log.info(f"HEC response: {r.status_code} {r.text}")
    except Exception as e:
        log.error(f"HEC send failed: {e}")


# ──────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────

def main():
    try:
        # ── Splunk passes results file path as argv[8] ─────
        # Format: sessionKey=... (URL-encoded) via stdin
        # Results: gzip-compressed CSV at argv[8]
        raw = sys.stdin.read().strip()
        log.info(f"sys.argv: {sys.argv}")

        results_file = None
        if len(sys.argv) > 8 and sys.argv[8]:
            results_file = sys.argv[8]
            log.info(f"Results file: {results_file}")

        if not results_file:
            log.error("No results file found in argv[8]")
            return

        # ── Read gzip-compressed CSV ───────────────────────
        if results_file.endswith('.gz'):
            opener = lambda: gzip.open(results_file, 'rt', encoding='utf-8')
        else:
            opener = lambda: open(results_file, 'r', encoding='utf-8')

        with opener() as f:
            reader = csv.DictReader(f)
            rows   = list(reader)

        log.info(f"Got {len(rows)} rows")

        # ── Process each Sysmon event row ──────────────────
        for row in rows:
            # Sysmon EventCode 1 fields — directly available
            cmd        = row.get('CommandLine', '')        or ''
            parent_cmd = row.get('ParentCommandLine', '')  or ''
            image      = row.get('Image', '')              or ''
            parent_img = row.get('ParentImage', '')        or ''
            orig_name  = row.get('OriginalFileName', '')   or ''
            host       = row.get('host', '') or row.get('ComputerName', 'unknown')
            event_code = int(row.get('EventCode', 1) or 1)

            log.info(f"CMD: {cmd[:80]} | Image: {image}")

            # ── Build Flask request payload ────────────────
            flask_payload = {
                "CommandLine"       : cmd,
                "ParentCommandLine" : parent_cmd,
                "Image"             : image,
                "ParentImage"       : parent_img,
                "OriginalFileName"  : orig_name,
                "EventID"           : event_code,
                "host"              : host
            }

            # ── Call Flask ML API ──────────────────────────
            response   = requests.post(FLASK_URL, json=flask_payload, timeout=15)
            prediction = response.json()

            # ── Build final event with taskguard_* fields ──
            final_event = {
                "taskguard_prediction"  : prediction.get("prediction", "UNKNOWN"),
                "taskguard_malicious"   : prediction.get("malicious", False),
                "taskguard_probability" : prediction.get("probability", 0.0),
                "taskguard_confidence"  : prediction.get("confidence", "LOW"),
                "taskguard_threshold"   : prediction.get("threshold", 0.5),
                "taskguard_model"       : "taskguard_xgboost_v1",
                "task_name"             : image.split("\\")[-1] if image else "unknown",
                "task_command"          : cmd,
                "task_image"            : image,
                "parent_image"          : parent_img,
                "source_host"           : host,
                "event_code"            : event_code,
                "taskguard_timestamp"   : datetime.now(timezone.utc).isoformat()
            }

            # ── Send to Splunk HEC ─────────────────────────
            send_to_hec(final_event)

            log.info(
                f"✓ DONE | img={image.split(chr(92))[-1]} | "
                f"prediction={final_event['taskguard_prediction']} | "
                f"prob={final_event['taskguard_probability']}"
            )
            print(json.dumps(final_event))

    except json.JSONDecodeError as e:
        log.error(f"JSON decode error: {e}")
    except requests.exceptions.ConnectionError:
        log.error("Flask API not reachable — is it running on port 5000?")
    except Exception as e:
        log.error(f"Unexpected error: {e}", exc_info=True)


if __name__ == '__main__':
    main()

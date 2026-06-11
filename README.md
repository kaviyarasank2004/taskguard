# TASKGUARD — ML-Based Detection of Malicious Windows Scheduled Tasks

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Splunk Enterprise](https://img.shields.io/badge/Splunk-Enterprise%209.x-green.svg)](https://www.splunk.com/)
[![XGBoost](https://img.shields.io/badge/XGBoost-2.x-orange.svg)](https://xgboost.readthedocs.io/)

**TASKGUARD** is a production-ready machine learning system that detects malicious Windows Scheduled Tasks in real time, integrated with Splunk Enterprise SIEM. It classifies scheduled task creation and execution events as **BENIGN** or **MALICIOUS** at up to **99.56% confidence** using a Word2Vec + XGBoost pipeline trained on 77,294 Sysmon samples.

Designed for Security Operations Center (SOC) analysts and blue teamers who want automated, ML-based detection of APT persistence techniques mapped to [MITRE ATT&CK T1053.005](https://attack.mitre.org/techniques/T1053/005/).

---

## Table of Contents

- [How It Works](#how-it-works)
- [Model Performance](#model-performance)
- [Quick Start](#quick-start)
- [File Structure](#file-structure)
- [Dependencies](#dependencies)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [Splunk Integration](#splunk-integration)
- [Model Details](#model-details)
- [Contributing](#contributing)
- [License](#license)

---

## How It Works

```
Windows 10 Endpoint
  └── Sysmon EventCode 1 (Process Create)
        └── Splunk Universal Forwarder → Splunk Enterprise
              └── Real-time Alert fires → splunk_alert.py
                    └── Flask API (app.py) on port 5000
                          └── Word2Vec + Scaler + XGBoost → MALICIOUS / BENIGN
                                └── Result → Splunk HEC → ml_prediction index
```

When a scheduled task is created or a process spawns on a monitored endpoint, Sysmon captures the event. The Splunk alert triggers `splunk_alert.py`, which extracts process fields, builds a 511-dimensional feature vector, and calls the Flask API for real-time ML inference. The prediction is written back into Splunk as a searchable `ml_prediction` event.

---

## Model Performance

| Metric | Value |
|--------|-------|
| AUC-ROC | 0.9993 |
| AUC-PR | 0.9984 |
| F1-Score | 99.03% |
| Precision | 98.62% |
| Recall | 99.45% |
| False Positive Rate | 0.07% |
| Live Detection Confidence | 99.56% |
| Training Dataset | 77,294 samples (TAPD) |
| Validation Dataset | 11,148 samples (TAPD-V) |

---

## Quick Start

### Prerequisites

- Ubuntu 20.04+ (or any Linux distro for the server)
- Python 3.12
- Splunk Enterprise 9.x
- Windows 10 endpoint with Sysmon64 + Splunk Universal Forwarder

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/taskguard.git
cd taskguard
```

### 2. Set up Python virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Add your model files

Place the three trained model files in the project root:

```
taskguard/
├── xgboost.joblib       ← XGBoost classifier (1.2 MB)
├── word2vec.joblib      ← Word2Vec embeddings (45 MB)
└── scaler.pkl           ← StandardScaler (13 KB)
```

> Model files are not included in this repository due to size. Download them from the [Releases](../../releases) page.

### 4. Configure the alert script

Open `splunk_alert.py` and set your HEC token:

```python
HEC_TOKEN = "your-splunk-hec-token-here"
```

### 5. Start the Flask API

```bash
source venv/bin/activate
python app.py
```

Verify it's running:

```bash
curl http://localhost:5000/health
```

Expected response:

```json
{
  "status": "running",
  "project": "TASKGUARD",
  "feature_count": 511,
  "threshold": 0.5,
  "w2v_vector_size": 100
}
```

### 6. Run as a background service (recommended)

```bash
sudo nano /etc/systemd/system/taskguard.service
```

```ini
[Unit]
Description=TASKGUARD Flask ML API
After=network.target

[Service]
User=YOUR_USERNAME
WorkingDirectory=/home/YOUR_USERNAME/taskguard
ExecStart=/home/YOUR_USERNAME/taskguard/venv/bin/python3 app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable taskguard
sudo systemctl start taskguard
```

---

## File Structure

```
taskguard/
├── app.py                  # Flask REST API — serves ML predictions on port 5000
├── splunk_alert.py         # Splunk alert action script — called by Splunk on each event
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── LICENSE                 # MIT License
│
└── models/                 # Model files (download separately from Releases)
    ├── xgboost.joblib      # Trained XGBoost classifier
    ├── word2vec.joblib     # Trained gensim Word2Vec model
    └── scaler.pkl          # Fitted StandardScaler
```

### `app.py`

The Flask REST API that loads all three model files at startup and serves inference requests. Exposes three endpoints:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Health check — confirms models loaded, returns feature count |
| `/predict` | POST | Main inference endpoint — accepts Sysmon fields, returns prediction |
| `/predict/splunk` | POST | Splunk-specific endpoint — accepts `result`-wrapped payload |

### `splunk_alert.py`

The Splunk alert action script deployed to `$SPLUNK_HOME/bin/scripts/`. Called automatically by Splunk's real-time alert system when a Sysmon EventCode 1 event is detected. Reads the gzip-compressed CSV results file from `argv[8]`, extracts Sysmon fields, calls the Flask API, and writes the prediction back to Splunk via HEC.

---

## Dependencies

```
flask>=3.0.0
xgboost>=2.0.0
gensim>=4.3.0
scikit-learn>=1.3.0
joblib>=1.3.0
numpy>=1.26.0
requests>=2.31.0
```

Install all dependencies:

```bash
pip install -r requirements.txt
```

> **Note:** TASKGUARD requires Python 3.12. The `splunk_alert.py` shebang points to the venv Python — ensure the path in line 1 matches your installation.

---

## Configuration

### `app.py` settings

| Variable | Default | Description |
|----------|---------|-------------|
| `MODEL_DIR` | `'/home/kavi/malicious_task_detector'` | Path to the directory containing model files |
| `THRESHOLD` | `0.5` | Classification threshold — events with probability ≥ 0.5 are MALICIOUS |

Update `MODEL_DIR` to match your deployment path:

```python
MODEL_DIR = '/path/to/your/taskguard'
```

### `splunk_alert.py` settings

| Variable | Description |
|----------|-------------|
| `FLASK_URL` | Flask API endpoint — default `http://localhost:5000/predict` |
| `HEC_URL` | Splunk HEC endpoint — default `http://localhost:8088/services/collector/event` |
| `HEC_TOKEN` | **Required** — your Splunk HEC token |
| `LOG_FILE` | Path to the alert log file |

---

## Usage Examples

### Direct API prediction

```bash
# Test with a benign command
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{
    "CommandLine": "C:\\Windows\\system32\\mmc.exe gpedit.msc",
    "ParentCommandLine": "explorer.exe",
    "Image": "C:\\Windows\\System32\\mmc.exe",
    "ParentImage": "C:\\Windows\\explorer.exe",
    "OriginalFileName": "mmc.exe",
    "EventID": 1
  }'
```

```json
{
  "prediction": "BENIGN",
  "malicious": false,
  "probability": 0.0001,
  "confidence": "LOW",
  "threshold": 0.5
}
```

```bash
# Test with a malicious command
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{
    "CommandLine": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -enc SGVsbG8=",
    "ParentCommandLine": "schtasks.exe /create /sc onlogon /tn Persistence",
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "ParentImage": "C:\\Windows\\System32\\schtasks.exe",
    "OriginalFileName": "powershell.exe",
    "EventID": 1
  }'
```

```json
{
  "prediction": "MALICIOUS",
  "malicious": true,
  "probability": 0.9956,
  "confidence": "HIGH",
  "threshold": 0.5
}
```

### Python client

```python
import requests

def check_task(command_line, image, parent_image="", original_filename=""):
    response = requests.post(
        "http://localhost:5000/predict",
        json={
            "CommandLine": command_line,
            "Image": image,
            "ParentImage": parent_image,
            "OriginalFileName": original_filename,
            "EventID": 1,
        }
    )
    result = response.json()
    print(f"Prediction : {result['prediction']}")
    print(f"Probability: {result['probability']:.4f}")
    print(f"Confidence : {result['confidence']}")
    return result

# Example usage
check_task(
    command_line='powershell.exe -ExecutionPolicy Bypass -enc SGVsbG8=',
    image='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    parent_image='C:\\Windows\\System32\\schtasks.exe'
)
```

### Querying predictions in Splunk

```spl
# View all malicious detections
index=main sourcetype=ml_prediction taskguard_malicious=true
| table _time, source_host, task_command, taskguard_prediction, taskguard_probability, taskguard_confidence
| sort - taskguard_probability

# Detection statistics by host
index=main sourcetype=ml_prediction
| stats count by source_host, taskguard_prediction
| sort - count

# High-confidence malicious events in last 24 hours
index=main sourcetype=ml_prediction taskguard_confidence=HIGH taskguard_malicious=true earliest=-24h
| table _time, source_host, task_command, taskguard_probability
```

---

## Splunk Integration

### Full setup guide

#### 1. Enable HTTP Event Collector (HEC)

In Splunk Web: **Settings → Data Inputs → HTTP Event Collector → Global Settings**

- All Tokens: **Enabled**
- Enable SSL: **Unchecked** (for local lab)
- HTTP Port: **8088**

Create a new token: **New Token → Name: `taskguard_predictions` → Source Type: `ml_prediction`**

Copy the token and paste it into `splunk_alert.py` at the `HEC_TOKEN` variable.

#### 2. Deploy the alert script

```bash
sudo cp splunk_alert.py /opt/splunk/bin/scripts/
sudo chmod +x /opt/splunk/bin/scripts/splunk_alert.py
sudo chown splunk:splunk /opt/splunk/bin/scripts/splunk_alert.py
```

Create the log file with write permissions for the splunk user:

```bash
sudo touch /home/kavi/malicious_task_detector/taskguard.log
sudo chmod 666 /home/kavi/malicious_task_detector/taskguard.log
```

Allow the splunk user to access the venv:

```bash
sudo chmod o+rx /home/YOUR_USERNAME
sudo chmod o+rx /home/YOUR_USERNAME/taskguard
sudo chmod -R o+rx /home/YOUR_USERNAME/taskguard/venv
```

#### 3. Configure Windows endpoint

In `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`:

```ini
[WinEventLog://Application]
index = main
disabled = false

[WinEventLog://Security]
index = main
disabled = false

[WinEventLog://System]
index = main
disabled = false

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = main
disabled = false
renderXml = false
```

Fix Sysmon log permissions (PowerShell as Administrator):

```powershell
wevtutil set-log "Microsoft-Windows-Sysmon/Operational" /ca:"O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;BO)(A;;0x1;;;SO)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;NS)"
Stop-Service SplunkForwarder -Force
Start-Service SplunkForwarder
```

#### 4. Create the Splunk real-time alert

In Splunk Web → Search & Reporting, run:

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where isnotnull(CommandLine) AND CommandLine!=""
| table _time, host, CommandLine, ParentCommandLine, Image, ParentImage, OriginalFileName
```

**Save As → Alert** with these settings:

| Setting | Value |
|---------|-------|
| Alert type | Real-time |
| Trigger | Per-Result |
| Action | Run a script → `splunk_alert.py` |

#### 5. Test end-to-end

On your Windows 10 endpoint (PowerShell as Administrator):

```powershell
schtasks /create /tn "TestMalicious" /tr "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -enc SGVsbG8=" /sc onlogon /f
```

Monitor the alert log:

```bash
tail -f ~/taskguard/taskguard.log
```

Expected log output within 60 seconds:

```
2026-06-10 12:00:00 [INFO] Got 1 rows
2026-06-10 12:00:00 [INFO] CMD: "C:\Windows\system32\schtasks.exe" /create /tn TestMalicious ...
2026-06-10 12:00:00 [INFO] HEC response: 200 {"text":"Success","code":0}
2026-06-10 12:00:00 [INFO] ✓ DONE | img=schtasks.exe | prediction=MALICIOUS | prob=0.9956
```

---

## Model Details

### Architecture

TASKGUARD uses a three-stage inference pipeline:

**Stage 1 — Text embeddings (500 dimensions)**
Five Sysmon process fields are vectorized using a trained Word2Vec (Skip-gram) model. Each field produces a 100-dimensional mean-pooled embedding:
- `CommandLine`
- `ParentCommandLine`
- `Image`
- `ParentImage`
- `OriginalFileName`

**Stage 2 — Domain features (11 dimensions)**
Behavioral and statistical features engineered from the raw event:

| Feature | Description | Cohen's d |
|---------|-------------|-----------|
| `dll_loading` | Sysmon EventID 7 indicator | **2.06** (strongest) |
| `cmd_entropy` | Shannon entropy of command string | 0.81 |
| `CommandExecutionCount` | Historical execution count | 1.57 |
| `TotalProcessExecutionCount` | Total process executions | 1.09 |
| `AvgTFIDFCommandRarity` | Command token rarity score | 1.05 |
| `cmd_length` | Character length of CommandLine | 0.74 |
| `cmd_token_count` | Token count in CommandLine | 0.68 |

**Stage 3 — XGBoost classification**
An XGBoost classifier trained on 511-dimensional scaled feature vectors with `scale_pos_weight=20.44` to compensate for the 20.44:1 class imbalance in the training dataset.

### Training dataset

| Property | Value |
|----------|-------|
| Dataset name | TAPD (Task-based APT Persistence Dataset) |
| Total samples | 77,294 |
| Benign samples | 73,689 (95.34%) |
| Malicious samples | 3,605 (4.66%) |
| Word2Vec vocabulary | 51,646 words |
| Validation dataset | TAPD-V (11,148 samples, unseen machines and tooling) |

### APT tools covered

Training data includes malicious samples generated by: GhostTask, Cobalt Strike, SharpPersist, and ScheduleRunner — covering persistence techniques used by APT41, APT29, APT32, Kimsuky, RedCurl, and others (MITRE T1053.005).

### Detection threshold

The default threshold is `0.5`. With `scale_pos_weight=20.44`, benign events score `0.45–0.49` and malicious events score `0.55–0.99`. Lowering the threshold increases recall at the cost of more false positives.

---

## Contributing

Contributions are welcome. Here's how to get involved:

### Reporting issues

Open a GitHub Issue with:
- Your Python version and OS
- The full error message and stack trace
- Steps to reproduce
- Your `app.py` configuration (redact any tokens)

### Pull requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes and add tests where applicable
4. Ensure the Flask API still passes the health check: `curl http://localhost:5000/health`
5. Submit a pull request with a clear description of what changed and why

### Areas that would benefit from contributions

- Additional Splunk dashboard XML for visualizing detection trends
- Support for other SIEM platforms (Elastic, QRadar)
- Docker containerization of the Flask API
- ONNX export of the model for broader compatibility
- Windows Event Log (non-Sysmon) fallback feature extraction

---

## Acknowledgements

- [TAPD Dataset](https://gitlab.cylab.be/cylab/daptask) — the training and validation dataset used to build this model
- [Sysinternals Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) — the telemetry source
- [MITRE ATT&CK T1053.005](https://attack.mitre.org/techniques/T1053/005/) — the threat technique this system detects
- [XGBoost](https://xgboost.readthedocs.io/) and [Gensim Word2Vec](https://radimrehurek.com/gensim/) — the core ML libraries

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

MIT was chosen because it:
- Allows free use, modification, and distribution
- Permits use in commercial security products and enterprise deployments
- Requires only attribution in derivative works
- Is compatible with all major open-source licenses used by this project's dependencies

```
MIT License

Copyright (c) 2026 Kaviyarasan K

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

*Built as a final year Computer Science Engineering project at DMI Engineering College, Anna University Chennai — April 2026.*

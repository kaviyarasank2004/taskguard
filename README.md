<div align="center">

```
████████╗ █████╗ ███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
   ██║   ███████║███████╗█████╔╝ ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
   ██║   ██╔══██║╚════██║██╔═██╗ ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
   ██║   ██║  ██║███████║██║  ██╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

**ML-Based Detection of Malicious Windows Scheduled Tasks**
*Integrated with Splunk Enterprise SIEM · Real-time · Production-Ready*

---

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![Splunk](https://img.shields.io/badge/Splunk-Enterprise_9.x-FF4500?style=for-the-badge&logo=splunk&logoColor=white)](https://www.splunk.com/)
[![XGBoost](https://img.shields.io/badge/XGBoost-2.x-0284c7?style=for-the-badge)](https://xgboost.readthedocs.io/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-T1053.005-dc2626?style=for-the-badge)](https://attack.mitre.org/techniques/T1053/005/)

---

| 🎯 AUC-ROC | ⚡ F1-Score | 🛡️ FPR | 🔬 Training Samples | 🚨 Live Confidence |
|:-----------:|:-----------:|:-------:|:-------------------:|:-----------------:|
| **0.9993** | **99.03%** | **0.07%** | **77,294** | **99.56%** |

</div>

---

## 📋 Table of Contents

- [How It Works](#-how-it-works)
- [Model Performance](#-model-performance)
- [Quick Start](#-quick-start)
- [File Structure](#-file-structure)
- [Dependencies](#-dependencies)
- [Configuration](#-configuration)
- [Usage Examples](#-usage-examples)
- [Splunk Integration](#-splunk-integration)
- [Model Details](#-model-details)
- [Contributing](#-contributing)
- [License](#-license)

---

## ⚙️ How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                    TASKGUARD PIPELINE                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Windows 10 Endpoint                                            │
│  └── Sysmon EventCode 1 (Process Create)                        │
│        └── Splunk Universal Forwarder → Splunk Enterprise       │
│              └── Real-time Alert fires → splunk_alert.py        │
│                    └── Flask API (app.py) on :5000              │
│                          └── Word2Vec + Scaler + XGBoost        │
│                                └── MALICIOUS / BENIGN           │
│                                      └── HEC → ml_prediction   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

When a scheduled task is created or a process spawns on a monitored endpoint, Sysmon captures the event. The Splunk alert triggers `splunk_alert.py`, which extracts process fields, builds a **511-dimensional feature vector**, and calls the Flask API for real-time ML inference. The prediction is written back into Splunk as a searchable `ml_prediction` event.

---

## 📊 Model Performance

<div align="center">

| Metric | Value | Interpretation |
|--------|-------|----------------|
| **AUC-ROC** | `0.9993` | Near-perfect class discrimination |
| **AUC-PR** | `0.9984` | Excellent on imbalanced data |
| **Precision** | `98.62%` | 717 TP / 727 predicted positive |
| **Recall** | `99.45%` | Missed only 4 of 721 malicious |
| **F1-Score** | `99.03%` | Balanced precision-recall |
| **False Positive Rate** | `0.07%` | 10 FP / 14,738 benign |
| **Live Detection** | `99.56%` | Confirmed on live Splunk endpoint |
| **Training Dataset** | `77,294 samples` | Full TAPD dataset |
| **Validation Dataset** | `11,148 samples` | TAPD-V (unseen machines) |

</div>

---

## 🚀 Quick Start

### Prerequisites

> **System Requirements**
> - Ubuntu 20.04+ server (or any Linux distro for the server)
> - Python 3.12
> - Splunk Enterprise 9.x
> - Windows 10 endpoint with Sysmon64 + Splunk Universal Forwarder

### 1. Clone the repository

```bash
git clone https://github.com/kaviyarasank2004/taskguard.git
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
├── xgboost.joblib       ← XGBoost classifier    (1.2 MB)
├── word2vec.joblib      ← Word2Vec embeddings   (45 MB)
└── scaler.pkl           ← StandardScaler        (13 KB)
```

> 📦 **Model files are not included in this repository due to size.**
> Download them from the [**Releases**](../../releases) page.

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

### 6. Run as a background service *(recommended)*

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

## 📁 File Structure

```
taskguard/
├── app.py                  # Flask REST API — ML inference on port 5000
├── splunk_alert.py         # Splunk alert script — triggered per Sysmon event
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── LICENSE                 # MIT License
│
└── models/                 # ⬇ Download from Releases
    ├── xgboost.joblib      # Trained XGBoost classifier
    ├── word2vec.joblib     # Trained gensim Word2Vec model
    └── scaler.pkl          # Fitted StandardScaler (511 features)
```

### `app.py` — Flask REST API

Loads all three model files at startup and serves inference requests.

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | `GET` | Confirms models loaded · returns feature count |
| `/predict` | `POST` | Main inference · accepts Sysmon fields |
| `/predict/splunk` | `POST` | Splunk-specific · accepts `result`-wrapped payload |

### `splunk_alert.py` — Splunk Alert Script

Deployed to `$SPLUNK_HOME/bin/scripts/`. Called automatically by Splunk's real-time alert on Sysmon EventCode 1. Reads the gzip-compressed CSV from `argv[8]`, extracts Sysmon fields, calls the Flask API, and writes the `taskguard_*` prediction back to Splunk via HEC.

---

## 📦 Dependencies

```
flask>=3.0.0
xgboost>=2.0.0
gensim>=4.3.0
scikit-learn>=1.3.0
joblib>=1.3.0
numpy>=1.26.0
requests>=2.31.0
```

```bash
pip install -r requirements.txt
```

> ⚠️ **Note:** TASKGUARD requires **Python 3.12**. The `splunk_alert.py` shebang points to the venv Python — ensure the path in line 1 matches your installation.

---

## 🔧 Configuration

### `app.py` settings

| Variable | Default | Description |
|----------|---------|-------------|
| `MODEL_DIR` | `'/home/kavi/malicious_task_detector'` | Path to model files directory |
| `THRESHOLD` | `0.5` | Classification threshold — events ≥ 0.5 → MALICIOUS |

Update `MODEL_DIR` to match your deployment path:

```python
MODEL_DIR = '/path/to/your/taskguard'
```

### `splunk_alert.py` settings

| Variable | Description |
|----------|-------------|
| `FLASK_URL` | Flask API endpoint — default `http://localhost:5000/predict` |
| `HEC_URL` | Splunk HEC endpoint — default `http://localhost:8088/services/collector/event` |
| `HEC_TOKEN` | ⚠️ **Required** — your Splunk HEC token |
| `LOG_FILE` | Path to the alert log file |

---

## 💻 Usage Examples

### Direct API prediction

```bash
# ✅ Benign command
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
# 🚨 Malicious command
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
            "CommandLine":      command_line,
            "Image":            image,
            "ParentImage":      parent_image,
            "OriginalFileName": original_filename,
            "EventID":          1,
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
# 🚨 All malicious detections
index=main sourcetype=ml_prediction taskguard_malicious=true
| table _time, source_host, task_command, taskguard_prediction,
        taskguard_probability, taskguard_confidence
| sort - taskguard_probability
```

```spl
# 📊 Detection statistics by host
index=main sourcetype=ml_prediction
| stats count by source_host, taskguard_prediction
| sort - count
```

```spl
# ⚡ High-confidence alerts — last 24 hours
index=main sourcetype=ml_prediction
  taskguard_confidence=HIGH taskguard_malicious=true earliest=-24h
| table _time, source_host, task_command, taskguard_probability
```

---

## 🔌 Splunk Integration

### Full setup guide

#### Step 1 — Enable HTTP Event Collector (HEC)

**Settings → Data Inputs → HTTP Event Collector → Global Settings**

| Setting | Value |
|---------|-------|
| All Tokens | **Enabled** |
| Enable SSL | **Unchecked** (local lab) |
| HTTP Port | **8088** |

Create token: **New Token → Name: `taskguard_predictions` → Source Type: `ml_prediction`**

Copy the token and paste it into `splunk_alert.py` at `HEC_TOKEN`.

---

#### Step 2 — Deploy the alert script

```bash
sudo cp splunk_alert.py /opt/splunk/bin/scripts/
sudo chmod +x /opt/splunk/bin/scripts/splunk_alert.py
sudo chown splunk:splunk /opt/splunk/bin/scripts/splunk_alert.py
```

Create the log file with write permissions:

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

---

#### Step 3 — Configure Windows endpoint

`C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

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

Fix Sysmon log permissions *(PowerShell as Administrator)*:

```powershell
wevtutil set-log "Microsoft-Windows-Sysmon/Operational" /ca:"O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;BO)(A;;0x1;;;SO)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;NS)"

Stop-Service SplunkForwarder -Force
Start-Service SplunkForwarder
```

---

#### Step 4 — Create the Splunk real-time alert

Run this search in Splunk Web → Search & Reporting:

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where isnotnull(CommandLine) AND CommandLine!=""
| table _time, host, CommandLine, ParentCommandLine, Image, ParentImage, OriginalFileName
```

**Save As → Alert** with these settings:

| Setting | Value |
|---------|-------|
| Alert type | `Real-time` |
| Trigger | `Per-Result` |
| Action | `Run a script` → `splunk_alert.py` |

---

#### Step 5 — Test end-to-end

On your Windows 10 endpoint *(PowerShell as Administrator)*:

```powershell
schtasks /create /tn "TestMalicious" `
  /tr "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -enc SGVsbG8=" `
  /sc onlogon /f
```

Monitor the alert log:

```bash
tail -f ~/taskguard/taskguard.log
```

Expected output within **60 seconds**:

```log
2026-06-10 12:00:00 [INFO] Got 1 rows
2026-06-10 12:00:00 [INFO] CMD: "C:\Windows\system32\schtasks.exe" /create /tn TestMalicious ...
2026-06-10 12:00:00 [INFO] HEC response: 200 {"text":"Success","code":0}
2026-06-10 12:00:00 [INFO] ✓ DONE | img=schtasks.exe | prediction=MALICIOUS | prob=0.9956
```

---

## 🧠 Model Details

### Architecture

TASKGUARD uses a three-stage inference pipeline producing a **511-dimensional feature vector**:

```
┌─────────────────────────────────────────────────────┐
│                  FEATURE PIPELINE                   │
├──────────────┬──────────────────────────────────────┤
│  TEXT BLOCK  │  500 dims — 5 fields × 100-dim W2V   │
│  (dims 0-499)│  CommandLine      [0:100]             │
│              │  ParentCommandLine[100:200]            │
│              │  Image            [200:300]            │
│              │  ParentImage      [300:400]            │
│              │  OriginalFileName [400:500]            │
├──────────────┼──────────────────────────────────────┤
│ DOMAIN BLOCK │  11 dims — behavioral features        │
│ (dims 500-510│  cmd_length, cmd_entropy, dll_loading │
│              │  execution counts, rarity scores ...  │
├──────────────┴──────────────────────────────────────┤
│  StandardScaler → XGBoost → P(MALICIOUS)            │
└─────────────────────────────────────────────────────┘
```

### Key domain features

| Feature | Cohen's d | Interpretation |
|---------|-----------|----------------|
| `dll_loading` | **2.06** ⭐ | Sysmon EventID 7 — strongest discriminator |
| `CommandExecutionCount` | **1.57** | Historical command frequency |
| `TotalProcessExecutionCount` | **1.09** | Total process invocations |
| `AvgTFIDFCommandRarity` | **1.05** | Rarity of command tokens in corpus |
| `cmd_entropy` | **0.81** | Shannon entropy of CommandLine characters |

### XGBoost configuration

```python
XGBClassifier(
    n_estimators       = 500,
    learning_rate      = 0.05,
    max_depth          = 6,
    subsample          = 0.8,
    colsample_bytree   = 0.8,
    scale_pos_weight   = 20.4408,   # CRITICAL — 20.44:1 class imbalance compensation
    eval_metric        = 'aucpr',   # Better than AUC-ROC for imbalanced data
    early_stopping_rounds = 50,
    best_iteration     = 464,
)
```

### Training dataset

| Property | Value |
|----------|-------|
| Dataset | TAPD (Task-based APT Persistence Dataset) |
| Total samples | 77,294 |
| Benign | 73,689 (95.34%) |
| Malicious | 3,605 (4.66%) |
| Word2Vec vocabulary | 51,646 words |
| Validation | TAPD-V — 11,148 samples, **unseen machines and tooling** |

### APT threat coverage

> Detects persistence techniques used by:
> **APT41** · **APT29** · **APT32** · **Kimsuky** · **RedCurl** · **Tarrask** · **FIN7** · **Lazarus Group**
>
> Mapped to [MITRE ATT&CK T1053.005](https://attack.mitre.org/techniques/T1053/005/)

### Detection threshold

The default threshold is `0.5`. With `scale_pos_weight=20.44`:

```
Benign tasks   →  probability 0.45 – 0.49  →  BENIGN
Malicious tasks →  probability 0.55 – 0.99  →  MALICIOUS
```

Lowering the threshold increases recall at the cost of more false positives.

---

## 🤝 Contributing

Contributions are welcome.

### Reporting issues

Open a GitHub Issue with:
- Python version and OS
- Full error message and stack trace
- Steps to reproduce
- Your `app.py` configuration *(redact any tokens)*

### Pull requests

```bash
# 1. Fork the repository
# 2. Create a feature branch
git checkout -b feature/your-feature-name

# 3. Make your changes, then push
git push origin feature/your-feature-name

# 4. Submit a Pull Request with a clear description
```

> Ensure the Flask API still passes the health check before submitting:
> ```bash
> curl http://localhost:5000/health
> # Expected: "feature_count": 511
> ```

### Areas that would benefit from contributions

- 📊 Splunk dashboard XML for visualizing detection trends
- 🐋 Docker containerization of the Flask API
- 🔌 Support for other SIEM platforms (Elastic, QRadar)
- 📦 ONNX export for broader model compatibility
- 🪟 Windows Event Log (non-Sysmon) fallback feature extraction

---

## 📚 Acknowledgements

| Resource | Role |
|----------|------|
| [TAPD Dataset](https://gitlab.cylab.be/cylab/daptask) | Training and validation dataset |
| [Sysinternals Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | Primary telemetry source |
| [MITRE ATT&CK T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Threat technique reference |
| [XGBoost](https://xgboost.readthedocs.io/) | Core classification library |
| [Gensim Word2Vec](https://radimrehurek.com/gensim/) | Semantic embedding library |

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

MIT was chosen because it:
- ✅ Allows free use, modification, and distribution
- ✅ Permits use in commercial security products and enterprise deployments
- ✅ Requires only attribution in derivative works
- ✅ Is compatible with all major open-source licenses used by this project's dependencies

---

<div align="center">

---

**TASKGUARD** · Built as a Final Year Project · DMI Engineering College, Anna University Chennai · 2026

*Kaviyarasan K*

[![GitHub](https://img.shields.io/badge/GitHub-kaviyarasank2004-181717?style=flat-square&logo=github)](https://github.com/kaviyarasank2004/taskguard)

---

*If this project helped you, consider giving it a ⭐ on GitHub*

</div>

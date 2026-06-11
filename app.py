#!/home/kavi/malicious_task_detector/venv/bin/python3
"""
TASKGUARD — Flask API for Splunk Integration
Matches exact 511-feature training pipeline:
  • 500 text features  = 5 fields × 100-dim Word2Vec
  • 11 domain features = cmd_length, cmd_token_count, cmd_entropy,
                         dll_loading, ProcessTreeDepth,
                         TotalProcessExecutionCount, HourlyProcessExecutionCount,
                         HourlyExecutionCountDelta, AvgTFIDFCommandRarity,
                         CommandExecutionCount, NormalizedCommandRarity

Feature layout (511 total):
  [0:100]   CommandLine       Word2Vec
  [100:200] ParentCommandLine Word2Vec
  [200:300] Image             Word2Vec
  [300:400] ParentImage       Word2Vec
  [400:500] OriginalFileName  Word2Vec
  [500]     cmd_length
  [501]     cmd_token_count
  [502]     cmd_entropy
  [503]     dll_loading
  [504]     ProcessTreeDepth
  [505]     TotalProcessExecutionCount
  [506]     HourlyProcessExecutionCount
  [507]     HourlyExecutionCountDelta
  [508]     AvgTFIDFCommandRarity
  [509]     CommandExecutionCount
  [510]     NormalizedCommandRarity
"""

from flask import Flask, request, jsonify
import joblib
import numpy as np
import math
import logging
from collections import Counter
from datetime import datetime, timezone

app = Flask(__name__)

# ── Logging ────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
log = logging.getLogger('taskguard-flask')

# ── Model Paths ────────────────────────────────────────────
MODEL_DIR   = '/home/kavi/malicious_task_detector'
XGB_PATH    = f'{MODEL_DIR}/xgboost.joblib'
W2V_PATH    = f'{MODEL_DIR}/word2vec.joblib'
SCALER_PATH = f'{MODEL_DIR}/scaler.pkl'

# ── Detection Threshold ────────────────────────────────────
# Production model uses scale_pos_weight=20.44
# Benign tasks score  → 0.45-0.49
# Malicious tasks score → 0.55-0.90
THRESHOLD = 0.5

# ── Load Models Once at Startup ────────────────────────────
try:
    xgb_model = joblib.load(XGB_PATH)
    w2v_model = joblib.load(W2V_PATH)
    scaler    = joblib.load(SCALER_PATH)
    log.info(
        f"✓ Models loaded | "
        f"W2V vector_size={w2v_model.vector_size} | "
        f"Scaler expects={scaler.n_features_in_} features"
    )
except Exception as e:
    log.critical(f"✗ Model load FAILED: {e}")
    raise

# ── The 5 text fields (ORDER MATTERS — must match training) ─
TEXT_FIELDS = [
    'CommandLine',
    'ParentCommandLine',
    'Image',
    'ParentImage',
    'OriginalFileName'
]

# ──────────────────────────────────────────────────────────
# FEATURE HELPERS
# ──────────────────────────────────────────────────────────

def get_w2v_vector(text: str) -> np.ndarray:
    """Average Word2Vec embeddings for all known tokens in text."""
    if not text or not isinstance(text, str):
        return np.zeros(w2v_model.vector_size)
    tokens = text.lower().split()
    vecs   = [w2v_model.wv[t] for t in tokens if t in w2v_model.wv]
    return np.mean(vecs, axis=0) if vecs else np.zeros(w2v_model.vector_size)


def cmd_entropy(cmd: str) -> float:
    """Shannon entropy of the command string characters."""
    if not cmd:
        return 0.0
    counts = Counter(cmd)
    total  = len(cmd)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def infer_dll_loading(data: dict) -> int:
    """
    Infer dll_loading feature from Sysmon EventID.
    Sysmon Event 7 = ImageLoaded (DLL loading) — dll_loading = 1
    All other events                            — dll_loading = 0
    Cohen's d = 2.06 (strongest single discriminator in the model)
    """
    eid = (
        data.get('EventID')   or
        data.get('eventid')   or
        data.get('event_id')  or
        data.get('EventCode')
    )
    if eid:
        try:
            return 1 if int(eid) == 7 else 0
        except (ValueError, TypeError):
            pass

    # Fallback: EventType string
    event_type = str(data.get('EventType', '')).lower()
    if 'imageload' in event_type or 'dllload' in event_type:
        return 1

    # Fallback: .dll extension in Image field
    image = str(data.get('Image', '')).lower()
    if image.endswith('.dll'):
        return 1

    return 0


def extract_features(data: dict) -> np.ndarray:
    """
    Build 511-dim feature vector matching training pipeline exactly.
    Called identically for /predict and /predict/splunk.
    """
    # ── 500 text features (5 × 100-dim Word2Vec) ──────────
    text_vecs = np.concatenate([
        get_w2v_vector(str(data.get(field, '') or ''))
        for field in TEXT_FIELDS
    ])

    # ── 11 domain features ────────────────────────────────
    cmd = str(data.get('CommandLine', '') or '')

    domain_feats = np.array([
        float(len(cmd)),
        float(len(cmd.split())),
        cmd_entropy(cmd),
        float(infer_dll_loading(data)),
        float(data.get('ProcessTreeDepth', 0)            or 0),
        float(data.get('TotalProcessExecutionCount', 1)  or 1),
        float(data.get('HourlyProcessExecutionCount', 1) or 1),
        float(data.get('HourlyExecutionCountDelta', 0)   or 0),
        float(data.get('AvgTFIDFCommandRarity', 0.0)     or 0.0),
        float(data.get('CommandExecutionCount', 1)       or 1),
        float(data.get('NormalizedCommandRarity', 0.0)   or 0.0),
    ], dtype=np.float32)

    return np.concatenate([text_vecs, domain_feats]).reshape(1, -1)


def confidence_band(prob: float) -> str:
    if prob >= 0.70:
        return 'HIGH'
    elif prob >= 0.40:
        return 'MEDIUM'
    return 'LOW'


# ──────────────────────────────────────────────────────────
# FLASK ENDPOINTS
# ──────────────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    """Health check — confirms all 3 models are loaded."""
    return jsonify({
        'status'          : 'running',
        'project'         : 'TASKGUARD',
        'w2v_vector_size' : int(w2v_model.vector_size),
        'feature_count'   : int(scaler.n_features_in_),
        'threshold'       : THRESHOLD,
        'timestamp'       : datetime.now(timezone.utc).isoformat()
    })


@app.route('/predict', methods=['POST'])
def predict():
    """
    Main prediction endpoint.
    Accepts Sysmon process event fields as JSON.

    Example:
    {
        "CommandLine":       "powershell.exe -ExecutionPolicy Bypass -enc ...",
        "ParentCommandLine": "schtasks.exe /create /sc onlogon",
        "Image":             "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "ParentImage":       "C:\\Windows\\System32\\schtasks.exe",
        "OriginalFileName":  "powershell.exe",
        "EventID":           1,
        "host":              "win-10"
    }
    """
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({'error': 'No JSON body received'}), 400

        features        = extract_features(data)
        features_scaled = scaler.transform(features)
        prob            = float(xgb_model.predict_proba(features_scaled)[0][1])
        is_malicious    = prob >= THRESHOLD

        result = {
            'prediction'  : 'MALICIOUS' if is_malicious else 'BENIGN',
            'malicious'   : is_malicious,
            'probability' : round(prob, 4),
            'confidence'  : confidence_band(prob),
            'threshold'   : THRESHOLD,
            'CommandLine' : data.get('CommandLine', ''),
            'Image'       : data.get('Image', ''),
            'host'        : data.get('host', 'unknown'),
            'timestamp'   : datetime.now(timezone.utc).isoformat()
        }

        log.info(
            f"PREDICT | prob={prob:.4f} | {result['prediction']} | "
            f"cmd={data.get('CommandLine','')[:80]}"
        )
        return jsonify(result)

    except Exception as e:
        log.error(f"PREDICT ERROR: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/predict/splunk', methods=['POST'])
def predict_splunk():
    """
    Splunk-specific endpoint.
    Accepts Splunk alert payload with event fields under 'result' key.
    Returns taskguard_* prefixed fields for clean Splunk indexing.
    """
    try:
        payload = request.get_json(force=True)
        if not payload:
            return jsonify({'error': 'No JSON body received'}), 400

        data = payload.get('result', payload)

        features        = extract_features(data)
        features_scaled = scaler.transform(features)
        prob            = float(xgb_model.predict_proba(features_scaled)[0][1])
        is_malicious    = prob >= THRESHOLD

        result = {
            'taskguard_prediction'  : 'MALICIOUS' if is_malicious else 'BENIGN',
            'taskguard_malicious'   : is_malicious,
            'taskguard_probability' : round(prob, 4),
            'taskguard_confidence'  : confidence_band(prob),
            'taskguard_threshold'   : THRESHOLD,
            'taskguard_model'       : 'taskguard_xgboost_v1',
            'source_CommandLine'    : data.get('CommandLine', ''),
            'source_Image'          : data.get('Image', ''),
            'source_host'           : data.get('host', 'unknown'),
            'taskguard_timestamp'   : datetime.now(timezone.utc).isoformat()
        }

        log.info(
            f"SPLUNK | prob={prob:.4f} | {result['taskguard_prediction']} | "
            f"host={data.get('host','?')} | "
            f"cmd={data.get('CommandLine','')[:60]}"
        )
        return jsonify(result)

    except Exception as e:
        log.error(f"SPLUNK PREDICT ERROR: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# ──────────────────────────────────────────────────────────
if __name__ == '__main__':
    log.info("Starting TASKGUARD Flask API on port 5000...")
    app.run(host='0.0.0.0', port=5000, debug=False)

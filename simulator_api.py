# simulator_api.py — FIXED with correct API format
from flask import Flask, request, jsonify, send_file
import os, pathlib, requests
import pandas as pd
from datetime import datetime, timezone

DATA_DIR = pathlib.Path("sim_data")
DATA_DIR.mkdir(exist_ok=True)
XLSX_PATH = DATA_DIR / "transcripts.xlsx"
SENT_LOG_PATH = DATA_DIR / "sent.xlsx"
RECEIVED_LOG_PATH = DATA_DIR / "received.xlsx"

app = Flask(__name__)

# Configuration
SIMULATOR_API_KEY = os.environ.get("SIMULATOR_API_KEY", "BKgVaqoVuLcQNOJP9ZBYsHQspMX_p3E_9I2e5eE05Gc")
APP_BASE_URL = os.environ.get("APP_BASE_URL", "https://servantlike-thermochemically-maison.ngrok-free.de").rstrip("/")

def load_df(path):
    """Load Excel file"""
    if path.exists():
        return pd.read_excel(path, index_col=0)
    return pd.DataFrame()

def save_df(df: pd.DataFrame, path):
    """Save to Excel"""
    df = df.fillna("")
    with pd.ExcelWriter(path, engine="openpyxl", mode="w") as w:
        df.to_excel(w)

def now_iso():
    """Current UTC timestamp"""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

# ============================================================================
# WEB INTERFACE
# ============================================================================

@app.route("/")
def index():
    """Serve the web interface"""
    html_path = pathlib.Path(__file__).parent / "simulator_web.html"
    if html_path.exists():
        return send_file(str(html_path))
    return '''
    <!DOCTYPE html>
    <html><head><title>Simulator</title></head>
    <body>
        <h1>Call Simulator</h1>
        <p>Please create simulator_web.html in the same directory</p>
        <p>Or use the API directly:</p>
        <pre>POST /forward-call?caller_id=+49111&destination_id=+49222</pre>
    </body></html>
    ''', 200

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.post("/forward-call")
def forward_call():
    """
    SIM REQ #1: Send transcript with CORRECT format
    
    Format: ?caller_id=+49111222333&destination_id=+4922197580971
    Body: {
        "transcript": {
            "customer_first_name": "Max",
            "customer_last_name": "Mustermann",
            "anliegen": ["..."],
            "next_steps": ["..."],
            "callback_number": "+49...",
            "email": "...",
            "ai_agent_name": "..."
        }
    }
    """
    # Get from query params (NEW FORMAT)
    caller_id = request.args.get("caller_id", "").strip()
    destination_id = request.args.get("destination_id", "").strip()
    
    # Get transcript from body
    j = request.get_json(force=True)
    transcript = j.get("transcript", {})
    
    if not caller_id or not destination_id or not transcript:
        return jsonify({"error": "caller_id, destination_id, and transcript required"}), 400

    # Log locally
    df = load_df(SENT_LOG_PATH)
    col = now_iso()
    log_entry = f"Caller: {caller_id} → Dest: {destination_id}\nSent: {col}"
    df.loc[destination_id, col] = log_entry
    save_df(df, SENT_LOG_PATH)
    
    # Forward to app with CORRECT format
    try:
        headers = {
            "Authorization": f"Bearer {SIMULATOR_API_KEY}",
            "Content-Type": "application/json"
        }
        
        # Use query params + body
        response = requests.post(
            f"{APP_BASE_URL}/api/forward-transcript",
            params={
                "caller_id": caller_id,
                "destination_id": destination_id
            },
            json={"transcript": transcript},
            headers=headers,
            timeout=10
        )
        
        response.raise_for_status()
        app_response = response.json()
        
        return jsonify({
            "ok": True,
            "caller_id": caller_id,
            "destination_id": destination_id,
            "forwarded_at": now_iso(),
            "status": "pending",
            "message": "Transcript will be shown when agent picks up",
            "app_response": app_response
        })
        
    except requests.exceptions.RequestException as e:
        return jsonify({
            "error": "Failed to forward to app",
            "details": str(e),
            "app_base_url": APP_BASE_URL
        }), 502

@app.post("/api/receive-transcript")
def receive_transcript():
    """
    SIM REQ #2: Receive completed call transcripts from app
    
    Format: ?caller_id=+49111&destination_id=+49222
    Body: { "transcript": "..." }
    """
    # Verify bearer token
    hdr = request.headers.get("Authorization", "")
    token = hdr[7:] if hdr.startswith("Bearer ") else hdr
    if not token or token != SIMULATOR_API_KEY:
        return jsonify({"error": "unauthorized"}), 401

    caller_id = request.args.get("caller_id", "").strip()
    destination_id = request.args.get("destination_id", "").strip()
    body = request.get_json(force=True)
    transcript = body.get("transcript", "")
    
    if not caller_id or not destination_id:
        return jsonify({"error": "caller_id and destination_id required"}), 400

    # Log received transcript
    df = load_df(RECEIVED_LOG_PATH)
    col = now_iso()
    log_entry = f"Caller: {caller_id} → Dest: {destination_id}\nReceived: {col}\nTranscript: {transcript}"
    df.loc[destination_id, col] = log_entry
    save_df(df, RECEIVED_LOG_PATH)
    
    print(f"✅ Received transcript back:")
    print(f"   Caller: {caller_id}")
    print(f"   Destination: {destination_id}")
    print(f"   Transcript: {transcript[:100]}...")
    
    return jsonify({
        "ok": True,
        "caller_id": caller_id,
        "destination_id": destination_id,
        "received_at": col,
        "message": "Transcript received and logged"
    })

@app.get("/health")
def health():
    """Health check"""
    return jsonify({
        "status": "healthy",
        "service": "call-simulator",
        "api_key_configured": bool(SIMULATOR_API_KEY),
        "app_base_url": APP_BASE_URL,
        "sent_count": len(load_df(SENT_LOG_PATH)),
        "received_count": len(load_df(RECEIVED_LOG_PATH))
    })

@app.get("/logs")
def logs():
    """View sent and received logs"""
    sent = load_df(SENT_LOG_PATH).to_dict()
    received = load_df(RECEIVED_LOG_PATH).to_dict()
    
    return jsonify({
        "sent": sent,
        "received": received
    })

# ============================================================================
# STARTUP
# ============================================================================

if __name__ == "__main__":
    print(f"API Key: {'✓' if SIMULATOR_API_KEY else '✗'}")
    print(f"App URL: {APP_BASE_URL}")
    print()
    print("  curl -X POST 'http://localhost:5000/forward-call?caller_id=+49111&destination_id=+49222' \\")
    print("    -H 'Content-Type: application/json' \\")
    print("    -d '{\"transcript\": {...}}'")
    app.run(host="0.0.0.0", port=5000, debug=True)

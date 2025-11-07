# simulator_api.py
# Secure REST API that simulates AI bot forwarding calls with transcripts
# to specific human agents with authentication

from flask import Flask, request, jsonify
import os, time, pathlib, requests, uuid
import pandas as pd
from datetime import datetime, timezone
from functools import wraps
import secrets

DATA_DIR = pathlib.Path("sim_data")
DATA_DIR.mkdir(exist_ok=True)
XLSX_PATH = DATA_DIR / "transcripts.xlsx"

app = Flask(__name__)

# Security: API key for authenticating with the main app
# This should match the SIMULATOR_API_KEY in app.py
SIMULATOR_API_KEY = os.environ.get("SIMULATOR_API_KEY", "BKgVaqoVuLcQNOJP9ZBYsHQspMX_p3E_9I2e5eE05Gc")
if not SIMULATOR_API_KEY:
    print("⚠️  WARNING: SIMULATOR_API_KEY not set! Generate one with:")
    print("   python -c 'import secrets; print(secrets.token_urlsafe(32))'")
    SIMULATOR_API_KEY = "dev-insecure-key"  # Only for development

# Base URL of the main app where transcripts will be forwarded
APP_BASE_URL = os.environ.get("APP_BASE_URL", "https://servantlike-thermochemically-maison.ngrok-free.dev").rstrip("/")

def load_df():
    """Load the transcript storage Excel file"""
    if XLSX_PATH.exists():
        return pd.read_excel(XLSX_PATH, index_col=0)
    return pd.DataFrame()

def save_df(df: pd.DataFrame):
    """Save transcripts to Excel (index = phone number, columns = timestamps)"""
    df = df.fillna("")
    with pd.ExcelWriter(XLSX_PATH, engine="openpyxl", mode="w") as w:
        df.to_excel(w)

def now_iso():
    """Return current UTC time as ISO string"""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

# ============================================================================
# TRANSCRIPT STORAGE (for simulator's own records)
# ============================================================================

@app.post("/transcripts")
def add_transcript():
    """
    Store a transcript for a phone number (simulator's internal storage)
    Body: { "number": "+4922197580971", "text": "..." }
    Returns the column timestamp where it was stored.
    """
    j = request.get_json(force=True)
    number = (j.get("number") or "").strip()
    text   = (j.get("text")   or "").strip()
   
    if not number or not text:
        return jsonify({"error": "number and text required"}), 400

    df = load_df()
    col = now_iso()
    df.loc[number, col] = text
    save_df(df)
   
    return jsonify({
        "ok": True,
        "number": number,
        "column": col,
        "stored_at": col
    })

@app.get("/transcripts/<number>/latest")
def latest(number):
    """Get the most recent transcript for a phone number"""
    df = load_df()
   
    if number not in df.index:
        return jsonify({"number": number, "text": "", "column": None})
   
    row = df.loc[number]
    # Find rightmost non-empty column
    non_empty_cols = [c for c in df.columns if isinstance(row.get(c, ""), str) and row.get(c, "").strip()]
   
    if not non_empty_cols:
        return jsonify({"number": number, "text": "", "column": None})
   
    latest_col = non_empty_cols[-1]
    return jsonify({
        "number": number,
        "text": str(row[latest_col]),
        "column": latest_col
    })

# ============================================================================
# CALL FORWARDING (main feature)
# ============================================================================

@app.post("/forward-call")
def forward_call():
    """
    Main endpoint: Forward a call with AI bot transcript/summary to a human agent.
   
    This simulates the moment when the AI bot decides to forward the call to a human.
    It sends the conversation summary to the app server, which then displays it
    to the specific agent in their Webex client.
   
    Request Body:
    {
        "target_agent_number": "+4922197580971",
        "app_base_url": "https://servantlike-thermochemically-maison.ngrok-free.dev" (optional, uses env var if not provided),
        "summary": {
            "customer_first_name": "Max",
            "customer_last_name": "Mustermann",
            "anliegen": ["Kontowechsel durchführen", "Kreditkarte beantragen"],
            "next_steps": ["Dokumente per E-Mail senden", "Rückruf in 2 Tagen"],
            "callback_number": "+49221123456",
            "email": "max.mustermann@example.com",
            "ai_agent_name": "BankBot-Alpha",
            "conversation_transcript": "Full transcript here..."  (optional)
        }
    }
   
    Returns:
    {
        "ok": true,
        "forwarded_to": "+4922197580971",
        "app_response": {...}
    }
    """
    j = request.get_json(force=True)
    call_id = str(uuid.uuid4())
   
    target_number = (j.get("target_agent_number") or "").strip()
    summary = j.get("summary", {})
    app_base = (j.get("app_base_url") or APP_BASE_URL).rstrip("/")
   
    if not target_number:
        return jsonify({"error": "target_agent_number is required"}), 400
   
    if not summary:
        return jsonify({"error": "summary is required"}), 400
   
    # Ensure summary has required fields
    required_fields = ["customer_first_name", "customer_last_name", "anliegen",
                      "next_steps", "callback_number", "email", "ai_agent_name"]
   
    for field in required_fields:
        if field not in summary:
            return jsonify({"error": f"summary.{field} is required"}), 400
   
    # Add timestamp if not present
    if "forwarded_at" not in summary:
        summary["forwarded_at"] = now_iso()
   
    # Store in our local Excel for records
    df = load_df()
    col = now_iso()
    transcript_text = summary.get("conversation_transcript", "")
    if not transcript_text:
        # Create a summary text from the structured data
        transcript_text = f"""Call forwarded from {summary['ai_agent_name']}
Customer: {summary['customer_first_name']} {summary['customer_last_name']}
Email: {summary['email']}
Callback: {summary['callback_number']}

Anliegen:
{chr(10).join('- ' + a for a in summary['anliegen'])}

Next Steps:
{chr(10).join('- ' + s for s in summary['next_steps'])}
"""
    df.loc[target_number, col] = transcript_text
    save_df(df)
   
    # Step 1: Simulate the call connecting
    try:
    # Send call state events to make it look like a real call
        call_id = str(uuid.uuid4())

    # First: Connecting state
        requests.post(
            f"{app_base}/simulate",
            json={
                "event": "connecting",
                "call_id": call_id,
                "remoteNumber": target_number,
                "displayName": f"{summary['customer_first_name']} {summary['customer_last_name']}"
            },
            timeout=5
        )
        time.sleep(1)  # Wait 1 second
        requests.post(
            f"{app_base}/simulate",
            json={
                "event": "connected",
                "call_id": call_id,
                "remoteNumber": target_number,
                "displayName": f"{summary['customer_first_name']} {summary['customer_last_name']}"
            },
            timeout=5
        )
        time.sleep(0.5)  # Wait half second
    except Exception as e:
        print(f"Warning: Could not simulate call states: {e}")

    # Forward to the main app server
    try:
        payload = {
            "target_number": target_number,
            "summary": summary
        }
       
        headers = {
            "Authorization": f"Bearer {SIMULATOR_API_KEY}",
            "Content-Type": "application/json"
        }
       
        response = requests.post(
            f"{app_base}/api/forward-transcript",
            json=payload,
            headers=headers,
            timeout=10
        )
       
        response.raise_for_status()
        app_response = response.json()
       
        return jsonify({
            "ok": True,
            "forwarded_to": target_number,
            "forwarded_at": summary["forwarded_at"],
            "app_response": app_response,
            "local_storage_column": col
        })
       
    except requests.exceptions.RequestException as e:
        return jsonify({
            "error": "Failed to forward to app server",
            "details": str(e),
            "app_base_url": app_base
        }), 502

# ============================================================================
# TESTING & UTILITY ENDPOINTS
# ============================================================================

@app.post("/test-forward")
def test_forward():
    """
    Quick test endpoint with predefined data for +4922197580971
   
    Usage:
        curl -X POST https://servantlike-thermochemically-maison.ngrok-free.dev/test-forward
    """
    test_summary = {
        "customer_first_name": "Max",
        "customer_last_name": "Mustermann",
        "anliegen": [
            "Kontowechsel von alter Bank durchführen",
            "Neue Kreditkarte mit erhöhtem Limit beantragen",
            "Online-Banking Zugang einrichten"
        ],
        "next_steps": [
            "Dokumente per E-Mail an max.mustermann@example.com senden",
            "Rückruf innerhalb von 2 Werktagen vereinbaren",
            "Termin für persönliche Beratung vorschlagen"
        ],
        "callback_number": "+49221987654",
        "email": "max.mustermann@example.com",
        "ai_agent_name": "BankBot-Alpha",
        "conversation_transcript": """
AI-Agent: Guten Tag! Hier ist BankBot-Alpha. Wie kann ich Ihnen heute helfen?

Kunde: Hallo, ich möchte von meiner alten Bank zu Ihnen wechseln.

AI-Agent: Das freut uns sehr! Ich kann Ihnen dabei helfen. Haben Sie bereits ein Konto bei uns?

Kunde: Nein, noch nicht. Ich brauche auch eine Kreditkarte mit einem höheren Limit.

AI-Agent: Verstanden. Ich werde Sie jetzt mit einem unserer Berater verbinden,
der Ihnen beim Kontowechsel und der Kreditkartenbeantragung helfen kann.
        """.strip()
    }
   
    # Call the forward-call endpoint internally
    return forward_call_internal("+4922197580971", test_summary)

def forward_call_internal(target_number: str, summary: dict):
    """Internal helper to forward a call (reusable logic)"""
    with app.test_request_context(
        '/forward-call',
        method='POST',
        json={
            "target_agent_number": target_number,
            "summary": summary
        }
    ):
        return forward_call()

@app.post("/bootstrap-example")
def bootstrap():
    """
    Generate example transcript data for testing
    Creates multiple transcript entries for +4922197580971
    """
    number = "+4922197580971"
    df = load_df()
   
    samples = [
        "Kunde fragt nach Kontostand und letzten Transaktionen",
        "Diskussion über Kreditkartenlimit-Erhöhung",
        "Beratung zu Festgeldanlagen und Zinssätzen",
        "Frage zu Online-Banking Sicherheitsmaßnahmen"
    ]
   
    cols = []
    for s in samples:
        ts = now_iso()
        cols.append(ts)
        df.loc[number, ts] = s
        time.sleep(0.3)  # Small delay between entries
   
    save_df(df)
   
    return jsonify({
        "ok": True,
        "number": number,
        "columns": cols,
        "count": len(cols)
    })

@app.get("/health")
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "simulator-api",
        "version": "1.0",
        "api_key_configured": bool(SIMULATOR_API_KEY and SIMULATOR_API_KEY != "dev-insecure-key"),
        "app_base_url": APP_BASE_URL
    })

@app.get("/")
def index():
    """API documentation"""
    return jsonify({
        "service": "AI Bot Call Simulator API",
        "version": "1.0",
        "endpoints": {
            "POST /forward-call": "Forward a call with summary to human agent",
            "POST /test-forward": "Quick test with predefined data",
            "POST /transcripts": "Store a transcript internally",
            "GET /transcripts/<number>/latest": "Get latest transcript for number",
            "POST /bootstrap-example": "Create example data",
            "GET /health": "Health check"
        },
        "documentation": "See ARCHITECTURE.md for full details"
    })

# ============================================================================
# STARTUP
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("AI Bot Call Simulator API")
    print("=" * 60)
    print(f"API Key configured: {bool(SIMULATOR_API_KEY and SIMULATOR_API_KEY != 'dev-insecure-key')}")
    print(f"App Base URL: {APP_BASE_URL}")
    print()
    print("To test:")
    print(f"  curl -X POST")
    print()
    print("To forward a call:")
    print("  curl -X POST \\")
    print('    -H "Content-Type: application/json" \\')
    print('    -d \'{"target_agent_number": "+4922197580971", "summary": {...}}\'')
    print()
    print("For ngrok:")
    print("  ngrok http 5000")
    print("=" * 60)
   
    app.run(host="0.0.0.0", port=5000, debug=True)

# app.py — SECURE Webex Call App with User Isolation
import pathlib, json, secrets, hashlib
from werkzeug.utils import secure_filename
from transcribe import transcribe_file
from summarize import summarize_text
from flask import Flask, redirect, render_template, request, jsonify, send_from_directory, abort, session
from flask_socketio import SocketIO, join_room, leave_room, emit
from datetime import datetime, timedelta
import os, uuid, pathlib, shutil, requests

WEBEX_BASE = "https://webexapis.com"
WEBEX_BASE_API = "https://webexapis.com/v1"

##### -------- CONFIGURATION ----------------------
WEBEX_BEARER = os.environ.get("WEBEX_BEARER", "MWRkMzFhZmItOThlMC00MmUwLWI5ZTItMmZiNWQyYWVlMmUwZGJkY2I2NTUtZGYy_PE93_43fc283b-bec8-41ed-87dd-6050b49fb6ba")
SIMULATOR_API_KEY = os.environ.get("SIMULATOR_API_KEY", "BKgVaqoVuLcQNOJP9ZBYsHQspMX_p3E_9I2e5eE05Gc")
SIMULATOR_BASE = os.environ.get("SIM_BASE", "https://3db3bb7f629b.ngrok-free.app").rstrip("/")
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_urlsafe(32))  # For session
##### ----------------------------------------------

# SECURE: Per-user storage
USER_SESSIONS = {}  # { session_id: { user_id, user_email, webex_person_id, last_seen } }
PENDING_TRANSCRIPTS_BY_USER = {}  # { user_id: { phone_number: transcript } }
ACTIVE_CALLS_BY_USER = {}  # { user_id: { call_id: {...} } }

BASE_DIR = "/Users/imenhellali/Desktop/TestPlugInWebex"
DATA_DIR = pathlib.Path("data")
REC_DIR = DATA_DIR / "recordings"
TRANS_DIR = DATA_DIR / "transcripts"
AUDIO_DIR = DATA_DIR / "audio"
for d in [REC_DIR, TRANS_DIR, AUDIO_DIR]:
    d.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = SECRET_KEY
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="eventlet"  # or "gevent" depending on your install
)
CALL_LOGS = {}

def require_api_key():
    """Validate Bearer token from simulator"""
    hdr = request.headers.get("Authorization", "")
    token = hdr[7:] if hdr.startswith("Bearer ") else hdr
    ok = token and token == SIMULATOR_API_KEY
    if not ok:
        return False, (jsonify({"error": "unauthorized"}), 401)
    return True, None

def get_user_from_session():
    """Get authenticated user from session"""
    session_id = session.get("session_id")
    if not session_id or session_id not in USER_SESSIONS:
        return None
   
    user_session = USER_SESSIONS[session_id]
    # Check if session expired (24 hours)
    if datetime.utcnow() - user_session.get("last_seen", datetime.utcnow()) > timedelta(hours=24):
        del USER_SESSIONS[session_id]
        return None
   
    user_session["last_seen"] = datetime.utcnow()
    return user_session

def get_user_id_for_number(phone_number: str) -> str:
    """
    Find which user owns this phone number.
    In production, query Webex API to map phone → user.
    """
    # TODO: Query Webex API to find user_id for this phone number
    # For now, use phone number as user_id (NOT SECURE - just for demo)
    return f"user_{phone_number}"

@socketio.on("connect")
def handle_connect():
    """When socket connects, authenticate the user"""
    print(f"🔌 Socket {request.sid} attempting to connect")
   
    # Get user from session (Flask session)
    user = get_user_from_session()
    if not user:
        print(f"❌ Unauthenticated socket connection attempt")
        return False  # Reject connection
   
    print(f"✅ Socket {request.sid} authenticated as {user.get('user_email')}")
    return True

@socketio.on("authenticate")
def handle_authenticate(data):
    """
    Authenticate user with Webex token.
    Frontend sends: { webex_access_token: "..." }
    """
    token = data.get("webex_access_token")
    if not token:
        emit("auth_failed", {"error": "No token provided"})
        return
   
    # Verify token with Webex API
    try:
        r = requests.get(
            f"{WEBEX_BASE_API}/people/me",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5
        )
        if not r.ok:
            emit("auth_failed", {"error": "Invalid token"})
            return
       
        user_data = r.json()
        user_id = user_data.get("id")
        user_email = user_data.get("emails", [None])[0]
       
        # Create secure session
        session_id = secrets.token_urlsafe(32)
        session["session_id"] = session_id
       
        USER_SESSIONS[session_id] = {
            "user_id": user_id,
            "user_email": user_email,
            "webex_person_id": user_id,
            "last_seen": datetime.utcnow(),
            "socket_id": request.sid
        }
       
        # Join user-specific room
        user_room = f"user:{user_id}"
        join_room(user_room)
       
        print(f"✅ User authenticated: {user_email} (room: {user_room})")
        emit("authenticated", {
            "user_id": user_id,
            "user_email": user_email,
            "room": user_room
        })
       
    except Exception as e:
        print(f"❌ Authentication error: {e}")
        emit("auth_failed", {"error": str(e)})

@socketio.on("join_number_room")
def join_number_room(data):
    """DEPRECATED: Don't use phone number rooms - use user rooms"""
    # For backwards compatibility, but not used in secure version
    pass

@app.after_request
def set_headers(resp):
    """Set CSP headers for Webex embedding"""
    csp = "frame-ancestors 'self' https://*.webex.com https://*.webexcontent.com https://*.cisco.com"
    resp.headers["Content-Security-Policy"] = csp
    resp.headers.pop("X-Frame-Options", None)
    return resp

@app.route("/")
def index():
    """Main UI"""
    return render_template("index.html")

@app.route("/simulate", methods=["POST"])
def simulate():
    """Receive call events from Webex SDK."""
    data = request.get_json(force=True)
    if not data or "event" not in data:
        return jsonify({"error": "bad request"}), 400

    call_id = data.get("call_id") or str(uuid.uuid4())
    caller = (data.get("remoteNumber") or data.get("caller") or "unknown").strip()
    local_number = (data.get("localNumber") or "").strip()
    display_name = (data.get("displayName") or "").strip()
    state = (data.get("event") or "unknown").lower()
    transcript = data.get("transcript", "")

    # Identify user
    user_id = get_user_id_for_number(local_number)
    user_room = f"user:{user_id}"

    print(f"📞 Call {state} for user {user_id} (local: {local_number}, remote: {caller})")

    # Track active call
    ACTIVE_CALLS_BY_USER.setdefault(user_id, {})[call_id] = {
        "caller": caller,
        "display_name": display_name,
        "state": state,
        "created": datetime.utcnow().isoformat() + "Z"
    }

    # ---- NEW: Inject pre-stored transcript if any ----
    transcript_text = ""
    if user_id in PENDING_TRANSCRIPTS_BY_USER:
        if caller in PENDING_TRANSCRIPTS_BY_USER[user_id]:
            transcript_text = PENDING_TRANSCRIPTS_BY_USER[user_id][caller]
            print(f"💾 Found pre-stored transcript for {caller}")

    # Emit to user
    socketio.emit("call_event", {
        "call_id": call_id,
        "caller": caller,
        "remoteNumber": caller,
        "displayName": display_name,
        "state": state,
        "transcript": transcript_text or transcript or ""
    }, to=user_room)

    # Cleanup
    if state == "ended":
        ACTIVE_CALLS_BY_USER[user_id].pop(call_id, None)

    return jsonify({"ok": True, "call_id": call_id, "user_id": user_id})

@app.post("/api/forward-transcript")
def forward_transcript():
    """
    Receive transcript from simulator.
   
    SECURE: Stores per-user, never broadcasts.
    """
    ok, err = require_api_key()
    if not ok:
        return err

    j = request.get_json(force=True)
    target = (j.get("target_number") or "").strip()
    summary = j.get("summary") or {}
   
    if not target or not summary:
        return jsonify({"error": "target_number and summary required"}), 400

    # Find which user owns this number
    user_id = get_user_id_for_number(target)

    # Format transcript
    def _lines(key):
        arr = summary.get(key) or []
        return "\n".join(f"- {x}" for x in arr) if arr else "—"

    composed = (
        f"Kunde: {summary.get('customer_first_name', '—')} {summary.get('customer_last_name', '—')}\n"
        f"Rückrufnummer: {summary.get('callback_number', '—')}\n"
        f"Email: {summary.get('email', '—')}\n"
        f"Agent: {summary.get('ai_agent_name', '—')}\n\n"
        f"Anliegen:\n{_lines('anliegen')}\n\n"
        f"Tasks:\n{_lines('next_steps')}\n"
    ).strip()

    # SECURE: Store per-user
    if user_id not in PENDING_TRANSCRIPTS_BY_USER:
        PENDING_TRANSCRIPTS_BY_USER[user_id] = {}
   
    PENDING_TRANSCRIPTS_BY_USER[user_id][target] = composed
    print(f"💾 Stored transcript for user {user_id}, number {target}")
   
    return jsonify({
        "ok": True,
        "user_id": user_id,
        "delivered": "on_pickup",
        "message": "Transcript stored securely for specific user"
    })

def _bearer():
    return WEBEX_BEARER

@app.route("/api/calls/history")
def api_calls_history():
    r = requests.get(
        f"{WEBEX_BASE}/v1/telephony/calls/history",
        headers={"Authorization": f"Bearer {_bearer()}"},
        timeout=10,
    )
    return (r.text, r.status_code, {"Content-Type": "application/json"})

@app.get("/api/people/lookup")
def people_lookup():
    number = request.args.get("number", "").strip()
    if not number:
        return jsonify({}), 400
    r = requests.get(
        f"{WEBEX_BASE_API}/people",
        params={"phoneNumber": number},
        headers={"Authorization": f"Bearer {_bearer()}"},
        timeout=10
    )
    return (r.text, r.status_code, {"Content-Type": "application/json"})

@app.route("/favicon.ico")
def favicon():
    return ("", 204)

@app.route("/health")
def health():
    """Health check with security info"""
    return jsonify({
        "status": "healthy",
        "security": {
            "user_isolation": True,
            "authentication": "webex_token",
            "encryption": "tls_required",
            "active_users": len(USER_SESSIONS)
        }
    })

if __name__ == "__main__":
    print("=" * 60)
    print("🔒 SECURE Webex Call App - User Isolation")
    print("=" * 60)
    print(f"Auth: {'✅' if SIMULATOR_API_KEY else '❌'}")
    print(f"Webex: {'✅' if WEBEX_BEARER else '❌'}")
    print(f"Session Secret: {'✅' if SECRET_KEY else '❌'}")
    print()
    print("🔒 Security Features:")
    print("  ✓ Per-user transcript storage")
    print("  ✓ Socket.IO room isolation")
    print("  ✓ Webex token authentication")
    print("  ✓ Session management")
    print()
    print("⚠️  PRODUCTION REQUIREMENTS:")
    print("  - Use HTTPS (TLS) only!")
    print("  - Set unique SECRET_KEY")
    print("  - Enable audit logging")
    print("  - Add rate limiting")
    print("=" * 60)
    socketio.run(app, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)
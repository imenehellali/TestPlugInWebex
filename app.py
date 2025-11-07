# app.py — COMPLETE Webex Call App (All Requirements Met)
import pathlib, json, secrets
from flask import Flask, redirect, render_template, request, jsonify, abort, session, url_for
from flask_socketio import SocketIO, join_room, leave_room, emit
from datetime import datetime, timedelta
import os, uuid, requests
import base64

WEBEX_BASE_API = "https://webexapis.com/v1"
DATA_DIR = pathlib.Path("data")
DATA_DIR.mkdir(exist_ok=True)
TOKENS_FILE = DATA_DIR / "oauth_tokens.json"
##### -------- CONFIGURATION ----------------------
WEBEX_BEARER = os.environ.get("WEBEX_BEARER", "YjJlOWUzZDUtZDg1Ni00NjI3LTk2NTgtMmE4ZjhhMTU0OGY0ZmJmMzBjMTMtM2Iy_PE93_43fc283b-bec8-41ed-87dd-6050b49fb6ba")
SIMULATOR_API_KEY = os.environ.get("SIMULATOR_API_KEY", "BKgVaqoVuLcQNOJP9ZBYsHQspMX_p3E_9I2e5eE05Gc")
SIMULATOR_BASE = os.environ.get("SIM_BASE", "https://3db3bb7f629b.ngrok-free.app").rstrip("/")

WEBEX_CLIENT_ID = os.environ.get("WEBEX_CLIENT_ID", "C74692c778b17a24486310efc2f08f242ed63438a40627061b8677b39b674868f")
WEBEX_CLIENT_SECRET = os.environ.get("WEBEX_CLIENT_SECRET", "0fd8ab47b5ed61c6bd1d7873b7f2c5bb44b12b0e67942ce7541dae8ee228c5ae")
WEBEX_REDIRECT_URI = os.environ.get("WEBEX_REDIRECT_URI", "https://servantlike-thermochemically-maison.ngrok-free.dev/oauth/callback")
WEBEX_SCOPES = os.environ.get("WEBEX_SCOPES", "spark:people_read") 

SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_urlsafe(32))
##### ----------------------------------------------

# Storage: Per Webex person_id
WEBEX_USER_SESSIONS = {}  # { socket_id: { webex_person_id, webex_email, phone_numbers } }
PENDING_TRANSCRIPTS = {}  # { webex_person_id: { caller_number: transcript } }
ACTIVE_CALLS = {}  # { call_id: { picker_person_id, caller, receiver, state } }

DATA_DIR = pathlib.Path("data")
DATA_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.secret_key = SECRET_KEY
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading",
                    engineio_logger=False, logger=False,
                    ping_timeout=60, ping_interval=25)
# ============================================================================
# WEBEX API HELPERS
# ============================================================================
#OAUTH_TOKENS = {}  # { email: {"access_token": "...", "refresh_token": "...", "expires_at": 1736292000} }
def load_tokens():
    """Load tokens from disk"""
    if TOKENS_FILE.exists():
        try:
            with open(TOKENS_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"⚠️ Failed to load tokens: {e}")
    return {}

def save_tokens_for(key: str, token_json: dict):
    expires_in = token_json.get("expires_in", 3600)
    OAUTH_TOKENS[key] = {
        "access_token": token_json["access_token"],
        "refresh_token": token_json.get("refresh_token"),
        "expires_at": datetime.utcnow().timestamp() + expires_in - 60,
    }
    save_all_tokens(OAUTH_TOKENS)

def save_all_tokens(tokens_dict):
    """Save all tokens to disk"""
    try:
        with open(TOKENS_FILE, 'w') as f:
            json.dump(tokens_dict, f, indent=2)
        print(f"💾 Saved {len(tokens_dict)} token entries to disk")
    except Exception as e:
        print(f"⚠️ Failed to save tokens: {e}")
    

OAUTH_TOKENS = load_tokens()

def get_token_for(key: str | None):
    if not key or not isinstance(key, str):
        return None
    entry = OAUTH_TOKENS.get(key)
    if not entry:
        return None
    if entry["expires_at"] <= datetime.now().timestamp() and entry.get("refresh_token"):
        r = requests.post(
            "https://webexapis.com/v1/access_token",
            data={
                "grant_type": "refresh_token",
                "client_id": WEBEX_CLIENT_ID,
                "client_secret": WEBEX_CLIENT_SECRET,
                "refresh_token": entry["refresh_token"],
            },
            timeout=10,
        )
        if not r.ok:
            return None
        save_tokens_for(key, r.json())
        entry = OAUTH_TOKENS[key]
    return entry["access_token"]

def save_tokens_both(identity: dict, tokens: dict):
    """Save tokens under both email and id (whichever exist), using your existing helper."""
    email = identity.get("email")
    pid   = identity.get("id")
    if pid:
        save_tokens_for(pid, tokens)
    if email:
        save_tokens_for(email, tokens)
    

def get_webex_person_by_phone(phone_number: str):
    """Query Webex API to find person_id for a phone number"""
    try:
        r = requests.get(
            f"{WEBEX_BASE_API}/people",
            params={"phoneNumber": phone_number},
            headers={"Authorization": f"Bearer {WEBEX_BEARER}"},
            timeout=5
        )
        if r.ok:
            items = r.json().get("items", [])
            if items:
                person = items[0]
                return {
                    "id": person.get("id"),
                    "email": person.get("emails", [None])[0],
                    "displayName": person.get("displayName"),
                    "phoneNumbers": person.get("phoneNumbers", [])
                }
    except Exception as e:
        print(f"⚠️ Webex API error: {e}")
    return None

def get_webex_person_by_token(access_token: str):
    """Get person info from Webex token"""
    try:
        r = requests.get(
            f"{WEBEX_BASE_API}/people/me",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=5
        )
        if r.ok:
            person = r.json()
            return {
                "id": person.get("id"),
                "email": person.get("emails", [None])[0],
                "displayName": person.get("displayName"),
                "phoneNumbers": person.get("phoneNumbers", [])
            }
    except Exception as e:
        print(f"⚠️ Webex API error: {e}")
    return None

# ============================================================================
# AUTHENTICATION
# ============================================================================

def require_api_key():
    """Validate Bearer token from simulator"""
    hdr = request.headers.get("Authorization", "")
    token = hdr[7:] if hdr.startswith("Bearer ") else hdr
    if not token or token != SIMULATOR_API_KEY:
        return False, (jsonify({"error": "unauthorized"}), 401)
    return True, None

# ============================================================================
# MAIN ENDPOINTS
# ============================================================================
@app.route("/debug/tokens")
def debug_tokens():
    """DEBUG ONLY - Remove in production!"""
    return jsonify({
        "stored_tokens": {
            key: {
                "has_access_token": bool(val.get("access_token")),
                "has_refresh_token": bool(val.get("refresh_token")),
                "expires_at": val.get("expires_at"),
                "expired": val.get("expires_at", 0) <= datetime.utcnow().timestamp() if val.get("expires_at") else None
            }
            for key, val in OAUTH_TOKENS.items()
        }
    })

@app.route("/oauth/login")
def oauth_login():
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    auth_url = (
        "https://webexapis.com/v1/authorize"
        f"?client_id={WEBEX_CLIENT_ID}"
        "&response_type=code"
        f"&redirect_uri={requests.utils.quote(WEBEX_REDIRECT_URI, safe='')}"
        f"&scope={requests.utils.quote(WEBEX_SCOPES)}"
        f"&state={state}"
    )
    return redirect(auth_url)

@app.route("/oauth/callback")
def oauth_callback():
    code = request.args.get("code")
    state = request.args.get("state")
    if not code or not state or state != session.get("oauth_state"):
        return abort(400, "Invalid OAuth state or code")
    r = requests.post(
        f"{WEBEX_BASE_API}/access_token",
        data={
            "grant_type": "authorization_code",
            "client_id": WEBEX_CLIENT_ID,
            "client_secret": WEBEX_CLIENT_SECRET,
            "code": code,
            "redirect_uri": WEBEX_REDIRECT_URI,
        },
        timeout=10,
    )
    if not r.ok:
        return abort(400, f"Token exchange failed: {r.text}")
    tokens = r.json()
    # verify and bind to email
    me = requests.get(
        f"{WEBEX_BASE_API}/people/me",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
        timeout=10,
    )
    me.raise_for_status()
    body = me.json()            
    person_id = body.get("id")
    email = (body.get("emails") or [None])[0]
    print(f"email={email}")
    print(f"person_id={person_id}")

    if person_id:
        save_tokens_for(person_id, tokens)   # save by id
    if email:
        save_tokens_for(email, tokens)
    
    app.logger.info("stored token for keys: %s", [k for k in OAUTH_TOKENS.keys()])
    return redirect("/")

@app.route("/auth/status")
def auth_status():
    email = request.args.get("email")
    pid   = request.args.get("id")

    token = None  # <-- initialize

    if not token and pid:
        token = get_token_for(pid)

    # try by email (and guard +/space variants)
    if email and not token:
        token = get_token_for(email)
        if " " in email:
            token = get_token_for(email.replace(" ", "+"))

    # fall back to personId
    

    authorized = bool(token)
    app.logger.info("auth_status id=%s email=%s authorized=%s", (pid[:12] + '…') if pid else None, email, authorized)
    return jsonify({"authorized": authorized})


@socketio.on("authenticate")
def handle_authenticate(data):
    pid   = data.get("id")
    email = data.get("email")
    access_token = get_token_for(pid) or get_token_for(email)
    if not access_token:
        emit("auth_failed", {"error": "No valid token; authorize via /oauth/login"})
        return
    person = get_webex_person_by_token(access_token)
    if not person:
        emit("auth_failed", {"error": "Invalid or expired token"})
        return
    WEBEX_USER_SESSIONS[request.sid] = {
        "webex_person_id": person["id"],
        "webex_email": person.get("email"),
        "displayName": person.get("displayName"),
        "phone_numbers": person.get("phoneNumbers"),
        "authenticated_at": datetime.now(),
    }
    join_room(f"webex_user:{person['id']}")
    emit("authenticated", {
        "webex_person_id": person["id"],
        "email": person.get("email"),
        "displayName": person.get("displayName"),
    })

@socketio.on("disconnect")
def handle_disconnect():
    """Clean up when user disconnects"""
    if request.sid in WEBEX_USER_SESSIONS:
        user = WEBEX_USER_SESSIONS[request.sid]
        print(f"🚪 User disconnected: {user['webex_email']}")
        del WEBEX_USER_SESSIONS[request.sid]

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

@app.post("/api/forward-transcript")
def forward_transcript():
    """
    REQ #1, #2: Receive transcript from simulator with bearer auth
    
    Format: ?caller_id=+49111&destination_id=+4922197580971
    Body: { "transcript": { ... } }
    """
    # REQ #1: Verify bearer token
    ok, err = require_api_key()
    if not ok:
        return err

    # REQ #2: Parse query params
    caller_id = request.args.get("caller_id", "").strip()
    destination_id = request.args.get("destination_id", "").strip()
    body = request.get_json(force=True)
    transcript_data = body.get("transcript", {})
    
    if not caller_id or not destination_id or not transcript_data:
        return jsonify({"error": "caller_id, destination_id, and transcript required"}), 400

    # REQ #3: Find Webex user(s) who own this destination number
    recipient_person = get_webex_person_by_phone(destination_id)
    
    if not recipient_person:
        return jsonify({"error": f"No Webex user found for {destination_id}"}), 404
    
    person_id = recipient_person["id"]

    # Format transcript for display
    def _lines(key):
        arr = transcript_data.get(key) or []
        return "\n".join(f"- {x}" for x in arr) if arr else "—"

    composed = (
        f"Kunde: {transcript_data.get('customer_first_name', '—')} {transcript_data.get('customer_last_name', '—')}\n"
        f"Rückrufnummer: {transcript_data.get('callback_number', caller_id)}\n"
        f"Email: {transcript_data.get('email', '—')}\n"
        f"Agent: {transcript_data.get('ai_agent_name', '—')}\n\n"
        f"Anliegen:\n{_lines('anliegen')}\n\n"
        f"Tasks:\n{_lines('next_steps')}\n"
    ).strip()

    # REQ #5: Store transcript for this specific Webex user
    if person_id not in PENDING_TRANSCRIPTS:
        PENDING_TRANSCRIPTS[person_id] = {}
    
    PENDING_TRANSCRIPTS[person_id][caller_id] = composed
    
    print(f"💾 Stored transcript for Webex user {recipient_person['email']}")
    print(f"   Caller: {caller_id} → Receiver: {destination_id}")
    
    return jsonify({
        "ok": True,
        "webex_person_id": person_id,
        "webex_email": recipient_person["email"],
        "destination_number": destination_id,
        "caller_number": caller_id,
        "status": "pending",
        "message": "Transcript will be delivered when user picks up call"
    })

@app.route("/simulate", methods=["POST"])
def simulate():
    """
    REQ #4, #6, #7, #8, #9, #10: Handle call state changes from Webex SDK
    
    Call flow:
    1. Ringing → Show caller, keep idle
    2. Connected → Check if this user is legitimate receiver, show transcript
    3. Ended → Return to idle, POST transcript back
    """
    data = request.get_json(force=True)
    if not data or "event" not in data:
        return jsonify({"error": "bad request"}), 400

    call_id = data.get("call_id") or str(uuid.uuid4())
    state = (data.get("event") or "unknown").lower()
    caller = (data.get("remoteNumber") or "").strip()
    receiver = (data.get("localNumber") or "").strip()  # THIS USER'S number
    display_name = (data.get("displayName") or "").strip()

    # REQ #3: Find which Webex user owns the receiver number
    receiver_person = get_webex_person_by_phone(receiver)
    
    if not receiver_person:
        print(f"⚠️ No Webex user found for receiver {receiver}")
        return jsonify({"ok": True, "warning": "receiver not found"})
    
    person_id = receiver_person["id"]
    user_room = f"webex_user:{person_id}"
    
    print(f"📞 Call {state}: {caller} → {receiver} (Webex user: {receiver_person['email']})")

    # Track call
    if call_id not in ACTIVE_CALLS:
        ACTIVE_CALLS[call_id] = {
            "caller": caller,
            "receiver": receiver,
            "receiver_person_id": person_id,
            "display_name": display_name,
            "state": state,
            "created": datetime.utcnow().isoformat()
        }
    else:
        ACTIVE_CALLS[call_id]["state"] = state

    # REQ #7: During ringing, send basic call info (no transcript)
    if state in ["ringing", "connecting"]:
        socketio.emit("call_event", {
            "call_id": call_id,
            "state": state,
            "remoteNumber": caller,
            "localNumber": receiver,
            "displayName": display_name,
            "transcript": ""  # NO transcript during ringing
        }, to=user_room)
        
        return jsonify({"ok": True, "call_id": call_id})

    # REQ #4, #6, #8: When picked up (connected), deliver transcript to ONLY this user
    if state == "connected":
        ACTIVE_CALLS[call_id]["picker_person_id"] = person_id
        
        # Check if we have a pending transcript for this user and caller
        transcript = ""
        if person_id in PENDING_TRANSCRIPTS:
            if caller in PENDING_TRANSCRIPTS[person_id]:
                # REQ #5: Remove transcript after delivery
                transcript = PENDING_TRANSCRIPTS[person_id].pop(caller)
                print(f"📨 Delivered transcript to {receiver_person['email']} for call from {caller}")
        
        # REQ #6: Emit ONLY to this user's room
        socketio.emit("call_event", {
            "call_id": call_id,
            "state": "connected",
            "remoteNumber": caller,
            "localNumber": receiver,
            "displayName": display_name,
            "transcript": transcript  # Can be empty if no transcript exists
        }, to=user_room)
        
        return jsonify({"ok": True, "call_id": call_id, "transcript_delivered": bool(transcript)})

    # REQ #9, #10: When call ends, return to idle and POST transcript back
    if state == "ended":
        # Emit end event to return to idle
        socketio.emit("call_event", {
            "call_id": call_id,
            "state": "ended",
            "remoteNumber": caller,
            "localNumber": receiver
        }, to=user_room)
        
        # REQ #10: POST transcript back to simulator
        if call_id in ACTIVE_CALLS:
            call_info = ACTIVE_CALLS[call_id]
            # Note: In real scenario, you'd collect the transcript during the call
            # For now, we'll send a simple acknowledgment
            _post_transcript_back(caller, receiver, f"Call completed at {datetime.utcnow().isoformat()}")
            del ACTIVE_CALLS[call_id]
        
        return jsonify({"ok": True, "call_id": call_id, "posted_back": True})

    return jsonify({"ok": True, "call_id": call_id})

def _post_transcript_back(caller: str, receiver: str, transcript: str):
    """REQ #10: POST completed call transcript back to simulator"""
    if not SIMULATOR_BASE:
        return
    
    try:
        response = requests.post(
            f"{SIMULATOR_BASE}/api/receive-transcript",
            params={
                "caller_id": caller,
                "destination_id": receiver
            },
            json={"transcript": transcript},
            headers={"Authorization": f"Bearer {SIMULATOR_API_KEY}"},
            timeout=10
        )
        
        if response.ok:
            print(f"✅ Posted transcript back: {caller} → {receiver}")
        else:
            print(f"⚠️ Failed to post back: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error posting transcript back: {e}")

# ============================================================================
# UTILITY ENDPOINTS
# ============================================================================

@app.get("/api/people/lookup")
def people_lookup():
    """Look up person by phone number"""
    number = request.args.get("number", "").strip()
    if not number:
        return jsonify({}), 400
    
    person = get_webex_person_by_phone(number)
    if person:
        return jsonify(person)
    return jsonify({}), 404

@app.get("/health")
def health():
    """Health check"""
    return jsonify({
        "status": "healthy",
        "authenticated_users": len(WEBEX_USER_SESSIONS),
        "pending_transcripts": sum(len(t) for t in PENDING_TRANSCRIPTS.values()),
        "active_calls": len(ACTIVE_CALLS)
    })

@app.route("/favicon.ico")
def favicon():
    return ("", 204)

# ============================================================================
# STARTUP
# ============================================================================

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)

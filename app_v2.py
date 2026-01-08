# app.py — Redesigned Webex Embedded App with proper architecture
import pathlib, json, secrets
from werkzeug.utils import secure_filename
from transcribe import transcribe_file
from summarize import summarize_text
from flask import Flask, redirect, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO
from flask_cors import CORS
from datetime import datetime
import os, uuid, json, pathlib, shutil, io, requests

WEBEX_BASE = "https://webexapis.com"
WEBEX_BASE_API = "https://webexapis.com/v1"

##### -------- TO MODIFY EVERY LOG IN ----------------------
WEBEX_BEARER = os.environ.get("WEBEX_BEARER", "MDFhYmEyMWUtODVmYy00MzI0LTgzNjgtNjBhMmZlNmM0ZGE0OTI5ZmE5MzktMmZh_PE93_43fc283b-bec8-41ed-87dd-6050b49fb6ba")
SIMULATOR_BASE = os.environ.get("SIM_BASE", "https://07e32cec2afb.ngrok-free.app")

# OAuth configuration for Webex Integration
WEBEX_CLIENT_ID = os.environ.get("WEBEX_CLIENT_ID", "C74692c778b17a24486310efc2f08f242ed63438a40627061b8677b39b674868f")
WEBEX_CLIENT_SECRET = os.environ.get("WEBEX_CLIENT_SECRET", "f479308b5f48da613013a307e08320856008e2fd5b49c8f83f8b8dbf240cb959")
WEBEX_REDIRECT_URI = os.environ.get("WEBEX_REDIRECT_URI", "https://servantlike-thermochemically-maison.ngrok-free.dev/oauth/callback")
# Use the actual scopes from the user's integration
WEBEX_SCOPES = "spark:calls_read spark:people_read spark-admin:people_read spark:recordings_read spark-compliance:recordings_read spark:calls_write spark:kms"

# Store access tokens (in production, use a database)
ACCESS_TOKENS = {}  # {user_id: {access_token, refresh_token, expires_at}}
##### ------------------------------------------------------

LAST_ACTIVE_BY_NUMBER = {}  # { "+4922...": "call_id" }
DATA_DIR = pathlib.Path("data")
REC_DIR = DATA_DIR / "recordings"
pathlib.Path(REC_DIR).mkdir(parents=True, exist_ok=True)
TRANS_DIR = DATA_DIR /"transcripts"
AUDIO_DIR = DATA_DIR /"audio"
pathlib.Path(TRANS_DIR).mkdir(parents=True, exist_ok=True)
pathlib.Path(AUDIO_DIR).mkdir(parents=True, exist_ok=True)

# Authorization and user management
AUTH_DIR = DATA_DIR / "auth"
pathlib.Path(AUTH_DIR).mkdir(parents=True, exist_ok=True)
AUTH_TOKENS = {}  # {token: {target_id, target_type, target_name, created}}
PENDING_CALLS = {}  # {target_id: [{call_id, caller, summary, timestamp}]}
ACTIVE_CALLS = {}  # {call_id: {assigned_to, target_id, target_type}}

# ========== V2 (Placetel AI Middleware) CONFIG & STORES ==========
# Secret must be exactly 16 characters. Set via env PLACETEL_AI_SECRET_16.
PLACETEL_AI_SECRET_16 = os.environ.get("PLACETEL_AI_SECRET_16", "").strip()

# V1 group membership resolution via webhooks:
# GROUP_MEMBERS[group_webex_uid] = set([user_webex_uid, ...])
GROUP_MEMBERS = {}

# V2 user mapping via webhooks:
# USER_TENANT[user_webex_uid] = admin_tenant
# USER_FORWARD_NUMBERS[user_webex_uid] = set([forward_number, ...])
USER_TENANT = {}
USER_FORWARD_NUMBERS = {}

# V2 pending transcripts and routing indices (all O(1) dict lookups)
# V2_PENDING[(admin_tenant, forward_number)][call_id] = payload_with_expiry
V2_PENDING = {}
# V2_CALL_INDEX[call_id] = (admin_tenant, forward_number)
V2_CALL_INDEX = {}
# V2_ACTIVE_CALLS[call_id] = {assigned_to, admin_tenant, forward_number, created}
V2_ACTIVE_CALLS = {}

# Unified history store (populated via webhooks; kept minimal and privacy-safe)
# HISTORY[user_webex_uid] = [{timestamp, version, direction, caller, forward_number, summary, call_id}, ...]
HISTORY = {}

# TTL for V2 pending payloads (seconds)
V2_TTL_SECONDS = int(os.environ.get("V2_TTL_SECONDS", "1800"))  # default 30 min


app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# in-memory store; persisted on call end
CALL_LOGS = {}  # {call_id: {caller, created, events:[{timestamp,state,transcript}], recording_url?}}

# Helper function to get bearer token
def _bearer():
    """Get the Webex bearer token from environment or default"""
    return WEBEX_BEARER

# Load AUTH_TOKENS from disk on startup
def load_auth_tokens():
    """Load all saved auth tokens from disk into memory"""
    print("[STARTUP] Loading auth tokens from disk...")
    count = 0
    for auth_file in AUTH_DIR.glob("*.json"):
        try:
            with open(auth_file, "r") as f:
                auth_data = json.load(f)
                # Token IS the Webex UID (target_id)
                token = auth_data["target_id"]
                AUTH_TOKENS[token] = auth_data
                count += 1
                print(f"[STARTUP] Loaded token for {auth_data.get('target_name', 'Unknown')}: {token[:20]}...")
        except Exception as e:
            print(f"[STARTUP] Error loading {auth_file}: {e}")
    print(f"[STARTUP] Loaded {count} auth tokens from disk")

# Load tokens on startup
load_auth_tokens()

# Socket.IO event handlers
@socketio.on('connect')
def handle_connect():
    print(f'Client connected: {request.sid}')

@socketio.on('disconnect')
def handle_disconnect():
    print(f'Client disconnected: {request.sid}')

@socketio.on("join")
def handle_join(data):
    from flask_socketio import join_room

    user_id = (data or {}).get("user_id")
    group_ids = (data or {}).get("group_ids") or []
    v2_rooms = (data or {}).get("v2_rooms") or []

    if user_id:
        join_room(user_id)
        print(f"User {user_id} joined room")

    # allow joining multiple group rooms (V1)
    for gid in group_ids:
        if gid and isinstance(gid, str):
            join_room(gid)
            print(f"User {user_id or request.sid} joined group room {gid}")

    # allow joining multiple V2 routing rooms (tenant+forward_number)
    for r in v2_rooms:
        if r and isinstance(r, str):
            join_room(r)
            print(f"User {user_id or request.sid} joined V2 room {r}")



    # allow joining multiple V2 routing rooms (tenant+forward_number)
    for r in v2_rooms:
        if r and isinstance(r, str):
            join_room(r)
            print(f"User {user_id or request.sid} joined V2 room {r}")



@socketio.on('leave')
def handle_leave(data):
    user_id = data.get('user_id')
    if user_id:
        from flask_socketio import leave_room
        leave_room(user_id)
        print(f'User {user_id} left room')

@app.after_request
def set_headers(resp):
    csp = "frame-ancestors 'self' https://*.webex.com https://*.webexcontent.com https://*.cisco.com"
    resp.headers["Content-Security-Policy"] = csp
    resp.headers.pop("X-Frame-Options", None)
    return resp

@app.route("/")
def index():
    return render_template("live.html")

@app.route("/live")
def live():
    return render_template("live.html")

@app.route("/history")
def history():
    return render_template("history.html")

@app.route("/authorization")
def authorization():
    return render_template("authorization.html")

@app.route("/simulator")
def simulator():
    return render_template("simulator.html")

@app.route("/webex_bridge.html")
def legacy_bridge():
    return redirect("/", code=302)

# ========== OAUTH FLOW ==========

@app.route("/oauth/start")
def oauth_start():
    """Initiate OAuth flow - redirect to Webex authorization"""
    if not WEBEX_CLIENT_ID:
        return jsonify({"error": "OAuth not configured. Set WEBEX_CLIENT_ID and WEBEX_CLIENT_SECRET environment variables."}), 500

    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)

    # Build authorization URL
    auth_url = (
        f"{WEBEX_BASE}/v1/authorize?"
        f"client_id={WEBEX_CLIENT_ID}&"
        f"response_type=code&"
        f"redirect_uri={WEBEX_REDIRECT_URI}&"
        f"scope={WEBEX_SCOPES}&"
        f"state={state}"
    )

    print(f"[oauth/start] Redirecting to: {auth_url}")
    return redirect(auth_url)

@app.route("/oauth/callback")
def oauth_callback():
    """Handle OAuth callback from Webex"""
    code = request.args.get("code")
    error = request.args.get("error")
    error_description = request.args.get("error_description")

    print(f"[oauth/callback] Received - code: {code[:20] if code else None}, error: {error}")

    if error:
        return jsonify({
            "error": error,
            "error_description": error_description
        }), 400

    if not code:
        return jsonify({"error": "No authorization code received"}), 400

    # Exchange code for access token
    try:
        token_url = f"{WEBEX_BASE}/v1/access_token"
        token_data = {
            "grant_type": "authorization_code",
            "client_id": WEBEX_CLIENT_ID,
            "client_secret": WEBEX_CLIENT_SECRET,
            "code": code,
            "redirect_uri": WEBEX_REDIRECT_URI
        }

        print(f"[oauth/callback] Exchanging code for token...")
        token_response = requests.post(token_url, data=token_data, timeout=10)

        if not token_response.ok:
            print(f"[oauth/callback] Token exchange failed: {token_response.status_code} - {token_response.text}")
            return jsonify({
                "error": "Token exchange failed",
                "details": token_response.text
            }), 500

        token_json = token_response.json()
        access_token = token_json.get("access_token")
        refresh_token = token_json.get("refresh_token")
        expires_in = token_json.get("expires_in", 3600)

        print(f"[oauth/callback] Token received! Expires in {expires_in}s")

        # Get user info
        user_response = requests.get(
            f"{WEBEX_BASE_API}/people/me",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10
        )

        if user_response.ok:
            user_info = user_response.json()
            user_id = user_info.get("id")

            # Store token
            ACCESS_TOKENS[user_id] = {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_at": datetime.utcnow().timestamp() + expires_in,
                "user_info": user_info
            }

            # Update global bearer token to use this one
            global WEBEX_BEARER
            WEBEX_BEARER = access_token

            print(f"[oauth/callback] Stored token for user: {user_info.get('displayName')} ({user_id})")

            return f"""
            <html>
            <head><title>Authorization Successful</title></head>
            <body style="font-family: system-ui; max-width: 600px; margin: 100px auto; text-align: center;">
                <h1 style="color: #18e299;">✓ Authorization Successful!</h1>
                <p>You have successfully authorized the app.</p>
                <p><strong>User:</strong> {user_info.get('displayName')}</p>
                <p><strong>Email:</strong> {user_info.get('emails', [''])[0]}</p>
                <p style="margin-top: 40px;">
                    <a href="/live" style="padding: 12px 24px; background: #18e299; color: #0b1020; text-decoration: none; border-radius: 8px; font-weight: 600;">
                        Go to App
                    </a>
                </p>
            </body>
            </html>
            """
        else:
            print(f"[oauth/callback] Failed to get user info: {user_response.status_code}")
            return jsonify({"error": "Failed to get user info"}), 500

    except Exception as e:
        print(f"[oauth/callback] Exception: {e}")
        return jsonify({"error": str(e)}), 500

# ========== END OAUTH FLOW ==========

# ========== AUTHORIZATION & USER MANAGEMENT ==========

@app.route("/api/auth/me")
def auth_me():
    """Get current user info from Webex"""
    bearer = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not bearer:
        bearer = _bearer()

    print(f"[auth_me] Using bearer token: {bearer[:20] if bearer else 'NONE'}...")

    try:
        r = requests.get(f"{WEBEX_BASE_API}/people/me",
                        headers={"Authorization": f"Bearer {bearer}"},
                        timeout=10)

        print(f"[auth_me] Response: {r.status_code}")

        if r.ok:
            user_data = r.json()
            print(f"[auth_me] User: {user_data.get('displayName')} (ID: {user_data.get('id', '')[:20]}...)")
            return jsonify(user_data)

        print(f"[auth_me] Error: {r.text[:200]}")
        return jsonify({"error": "unauthorized", "details": r.text}), 401
    except Exception as e:
        print(f"[auth_me] Exception: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/users/list")
def list_users():
    """List all users (requires admin scope)"""
    try:
        bearer = _bearer()
        print(f"[list_users] Using bearer token: {bearer[:20]}...")
        r = requests.get(f"{WEBEX_BASE_API}/people",
                        headers={"Authorization": f"Bearer {bearer}"},
                        params={"max": 100},
                        timeout=10)
        print(f"[list_users] Webex API response: {r.status_code}")
        if not r.ok:
            print(f"[list_users] Error response: {r.text[:200]}")
        return (r.text, r.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        print(f"[list_users] Exception: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/groups/list")
def list_groups():
    """List all workspaces/user groups (requires admin scope)"""
    try:
        # Note: Webex uses "workspaces" for user groups
        r = requests.get(f"{WEBEX_BASE_API}/workspaces",
                        headers={"Authorization": f"Bearer {_bearer()}"},
                        params={"max": 100},
                        timeout=10)
        return (r.text, r.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/auth/generate", methods=["POST"])
def generate_auth_token():
    """
    Generate a POST API endpoint for a user/group.
    Body: {target_id, target_type: 'user'|'group'|'external', target_name}
    Returns: {token, post_url}

    NOTE: We use the Webex UID directly as the token (no random generation).
    The token IS the Webex UID, which is also the Socket.IO room name.
    """
    data = request.get_json(force=True)
    target_id = data.get("target_id")
    target_type = data.get("target_type")  # user, group, external
    target_name = data.get("target_name", "")

    print(f"[generate_auth_token] Request: target_id={target_id[:20] if target_id else None}..., target_type={target_type}, target_name={target_name}")

    if not target_id or not target_type:
        return jsonify({"error": "target_id and target_type required"}), 400

    # Use Webex UID directly as token (no random generation)
    token = target_id

    # Store metadata (token = Webex UID)
    AUTH_TOKENS[token] = {
        "target_id": target_id,
        "target_type": target_type,
        "target_name": target_name,
        "created": datetime.utcnow().isoformat() + "Z"
    }

    print(f"[generate_auth_token] Using Webex UID as token: {token[:20]}...")

    # Save to disk
    auth_file = AUTH_DIR / f"{target_id}.json"
    with open(auth_file, "w") as f:
        json.dump(AUTH_TOKENS[token], f, indent=2)

    # Generate POST URL - token is the Webex UID
    base_url = request.host_url.rstrip("/")
    post_url = f"{base_url}/api/forward/{token}"

    return jsonify({
        "token": token,
        "post_url": post_url,
        "target_id": target_id,
        "target_type": target_type,
        "target_name": target_name
    })

@app.route("/api/forward/test", methods=["GET", "POST"])
def test_forward_endpoint():
    """Test endpoint to verify /api/forward/* is accessible"""
    print(f"[test_forward_endpoint] Test endpoint hit! Method: {request.method}")
    print(f"[test_forward_endpoint] Currently loaded AUTH_TOKENS: {len(AUTH_TOKENS)}")
    for token, info in AUTH_TOKENS.items():
        print(f"  - {token[:30]}... → {info.get('target_name', 'Unknown')}")
    return jsonify({
        "status": "ok",
        "message": "Test endpoint working",
        "tokens_loaded": len(AUTH_TOKENS),
        "method": request.method
    })

@app.route("/api/forward/<token>", methods=["POST", "OPTIONS"])
def forward_call(token):
    """
    Receive AI call summary and forward to appropriate user/group.
    Body: {caller, summary, agent_name, customer_name, customer_number, customer_email, concerns, tasks}
    """
    # Handle CORS preflight
    if request.method == "OPTIONS":
        response = jsonify({"status": "ok"})
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "POST,OPTIONS")
        return response, 200

    print(f"\n{'='*80}")
    print(f"[forward_call] ===== INCOMING POST REQUEST =====")
    print(f"[forward_call] Token received: {token}")
    print(f"[forward_call] Token length: {len(token)}")
    print(f"[forward_call] Request headers: {dict(request.headers)}")
    print(f"[forward_call] Request content type: {request.content_type}")
    print(f"[forward_call] Raw request data: {request.get_data(as_text=True)[:500]}")

    # Debug: Show all loaded tokens
    print(f"[forward_call] Currently loaded tokens in AUTH_TOKENS:")
    for loaded_token, info in AUTH_TOKENS.items():
        print(f"  - Token: {loaded_token[:30]}... → {info.get('target_name', 'Unknown')}")

    if token not in AUTH_TOKENS:
        print(f"[forward_call] ❌ TOKEN NOT FOUND IN AUTH_TOKENS!")
        print(f"[forward_call] Expected token: {token}")
        print(f"[forward_call] Available tokens: {list(AUTH_TOKENS.keys())}")
        return jsonify({"error": "invalid token", "token_received": token[:20], "tokens_available": len(AUTH_TOKENS)}), 401

    auth_info = AUTH_TOKENS[token]
    target_id = auth_info["target_id"]
    target_type = auth_info["target_type"]

    print(f"[forward_call] ✓ Token valid! Maps to: target_id={target_id[:20]}..., target_type={target_type}")

    try:
        data = request.get_json(force=True)
        print(f"[forward_call] Parsed JSON data: {json.dumps(data, indent=2)}")
    except Exception as e:
        print(f"[forward_call] ❌ Failed to parse JSON: {e}")
        return jsonify({"error": "invalid json", "details": str(e)}), 400

    caller = data.get("caller", "")
    summary = data.get("summary", "")

    # Extract structured data
    call_data = {
        "agent_name": data.get("agent_name", "AI Assistant"),
        "customer_name": data.get("customer_name", "—"),
        "customer_number": data.get("customer_number", caller or "—"),
        "customer_email": data.get("customer_email", "—"),
        "concerns": data.get("concerns", []),
        "tasks": data.get("tasks", [])
    }

    call_id = str(uuid.uuid4())

    # Store in pending calls
    if target_id not in PENDING_CALLS:
        PENDING_CALLS[target_id] = []

    PENDING_CALLS[target_id].append({
        "call_id": call_id,
        "caller": caller,
        "summary": summary,
        "call_data": call_data,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "target_type": target_type
    })

    # Emit socket event based on target type
    if target_type == "user" or target_type == "external":
        # Single user - immediately show full summary
        print(f"[forward_call] Emitting 'incoming_call' to Webex UID room: {target_id[:20]}...")
        socketio.emit("incoming_call", {
            "call_id": call_id,
            "caller": caller,
            "target_id": target_id,
            "target_type": target_type,
            "show_summary": True,
            "call_data": call_data,
            "summary": summary
        }, room=target_id)
        print(f"[forward_call] Socket event emitted successfully")
    elif target_type == "group":
        # User group - show caller number only, wait for pickup
        print(f"[forward_call] Emitting 'incoming_call' (group) to room: {target_id[:20]}...")
        socketio.emit("incoming_call", {
            "call_id": call_id,
            "caller": caller,
            "target_id": target_id,
            "target_type": target_type,
            "show_summary": False,
            "call_data": None,
            "summary": None
        }, room=target_id)
        print(f"[forward_call] Socket event emitted successfully")

        # V1 enhancement: if this group UID represents a queue/workspace,
        # resolve members via webhook-fed GROUP_MEMBERS and notify them directly.
        members = list(GROUP_MEMBERS.get(target_id, set()))
        if members:
            print(f"[forward_call] Group membership resolved via webhook: {len(members)} member(s)")
            for member_id in members:
                socketio.emit("incoming_call", {
                    "call_id": call_id,
                    "caller": caller,
                    "target_id": target_id,
                    "target_type": target_type,
                    "show_summary": False,
                    "call_data": None,
                    "summary": None
                }, room=member_id)
        else:
            print("[forward_call] No webhook group membership found for this group UID (GROUP_MEMBERS empty)")

    print(f"[forward_call] ✓ SUCCESS! Returning call_id: {call_id}")
    print(f"{'='*80}\n")
    return jsonify({"ok": True, "call_id": call_id})

@app.route("/api/call/pickup", methods=["POST"])
def pickup_call():
    """
    Assign a pending call to a user (first-pickup-wins).
    Body:
      - V1: {call_id, user_id, version?: "v1"}
      - V2: {call_id, user_id, version: "v2"}
    """
    data = request.get_json(force=True) or {}
    call_id = data.get("call_id")
    user_id = data.get("user_id")
    version = (data.get("version") or "v1").lower()

    if not call_id or not user_id:
        return jsonify({"error": "call_id and user_id required"}), 400

    # =========================
    # V2 pickup
    # =========================
    if version == "v2":
        key = V2_CALL_INDEX.get(call_id)
        if not key:
            return jsonify({"error": "call not found (v2)", "call_id": call_id}), 404

        admin_tenant, forward_number = key
        bucket = V2_PENDING.get((admin_tenant, forward_number), {})
        call_info = bucket.get(call_id)
        if not call_info:
            return jsonify({"error": "call not pending (v2)", "call_id": call_id}), 404

        # Mark active and remove from pending immediately (security)
        V2_ACTIVE_CALLS[call_id] = {
            "assigned_to": user_id,
            "admin_tenant": admin_tenant,
            "forward_number": forward_number,
            "created": datetime.utcnow().isoformat() + "Z"
        }
        bucket.pop(call_id, None)
        if not bucket:
            V2_PENDING.pop((admin_tenant, forward_number), None)

        V2_CALL_INDEX.pop(call_id, None)

        # Notify assignee
        socketio.emit("call_assigned", {
            "call_id": call_id,
            "caller": call_info.get("caller", ""),
            "show_summary": True,
            "call_data": call_info.get("call_data"),
            "summary": call_info.get("summary"),
            "version": "v2",
            "admin_tenant": admin_tenant,
            "forward_number": forward_number
        }, room=user_id)

        # Remove from shared queue room
        queue_room = f"v2:{admin_tenant}:{forward_number}"
        socketio.emit("call_removed", {"call_id": call_id, "version": "v2"}, room=queue_room)

        # History (minimal)
        HISTORY.setdefault(user_id, []).insert(0, {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "version": "v2",
            "direction": "inbound",
            "caller": call_info.get("caller", ""),
            "forward_number": forward_number,
            "summary": call_info.get("summary", ""),
            "call_id": call_id
        })
        return jsonify({"ok": True, "assigned_to": user_id, "version": "v2"})

    # =========================
    # V1 pickup (existing behavior)
    # =========================
    call_info = None
    target_id = None
    for tid, calls in PENDING_CALLS.items():
        for c in calls:
            if c["call_id"] == call_id:
                call_info = c
                target_id = tid
                break
        if call_info:
            break

    if not call_info or not target_id:
        return jsonify({"error": "call not found"}), 404

    ACTIVE_CALLS[call_id] = {
        "assigned_to": user_id,
        "target_id": target_id,
        "target_type": call_info["target_type"]
    }

    # Remove from pending
    PENDING_CALLS[target_id] = [c for c in PENDING_CALLS[target_id] if c["call_id"] != call_id]

    # Emit to user who picked up
    socketio.emit("call_assigned", {
        "call_id": call_id,
        "caller": call_info["caller"],
        "show_summary": True,
        "call_data": call_info["call_data"],
        "summary": call_info["summary"],
        "version": "v1"
    }, room=user_id)

    # Emit to others in group that call is no longer available
    if call_info["target_type"] == "group":
        socketio.emit("call_removed", {"call_id": call_id, "version": "v1"}, room=target_id)

    HISTORY.setdefault(user_id, []).insert(0, {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": "v1",
        "direction": "inbound",
        "caller": call_info.get("caller", ""),
        "forward_number": None,
        "summary": call_info.get("summary", ""),
        "call_id": call_id
    })

    return jsonify({"ok": True, "assigned_to": user_id, "version": "v1"})


# ========== V2 MIDDLEWARE + WEBHOOKS ==========
def _parse_v2_bearer():
    """Parse Authorization header for V2.
    Expected: Authorization: Bearer <16-char-secret>:<admin_tenant>
    Returns: (secret, admin_tenant) or (None, None)
    """
    raw = (request.headers.get("Authorization") or "").strip()
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
    if not raw:
        return None, None
    if ":" not in raw:
        return raw, None
    secret, admin_tenant = raw.split(":", 1)
    return secret.strip(), (admin_tenant or "").strip()

def _require_v2_auth(body_admin_tenant: str):
    secret, header_tenant = _parse_v2_bearer()

    if not PLACETEL_AI_SECRET_16 or len(PLACETEL_AI_SECRET_16) != 16:
        return False, ("server misconfigured: PLACETEL_AI_SECRET_16 must be set to 16 chars", 500)

    if not secret or secret != PLACETEL_AI_SECRET_16:
        return False, ("unauthorized: invalid bearer secret", 401)

    if not header_tenant:
        return False, ("unauthorized: missing admin tenant in bearer header", 401)

    if body_admin_tenant and header_tenant != body_admin_tenant:
        return False, ("unauthorized: admin tenant mismatch (header vs body)", 401)

    return True, header_tenant

def _v2_room(admin_tenant: str, forward_number: str) -> str:
    return f"v2:{admin_tenant}:{forward_number}"

@app.route("/api/v2/rooms", methods=["GET"])
def v2_rooms_for_user():
    """Return the Socket.IO rooms the user should join for V2 routing."""
    user_id = request.args.get("user_id", "").strip()
    if not user_id:
        return jsonify({"error": "user_id required"}), 400

    admin_tenant = USER_TENANT.get(user_id)
    forwards = sorted(USER_FORWARD_NUMBERS.get(user_id, set()))
    rooms = []
    if admin_tenant:
        for fwd in forwards:
            rooms.append(_v2_room(admin_tenant, fwd))
    return jsonify({
        "user_id": user_id,
        "admin_tenant": admin_tenant,
        "forward_numbers": forwards,
        "rooms": rooms
    })

@app.route("/api/v2/placetelAIMiddleWare", methods=["POST", "OPTIONS"])
def placetel_ai_middleware_v2():
    """
    V2: Receive transcripts keyed by (admin_tenant, forward_number), protected by bearer secret.
    Required fields: admin_tenant, forward_number, caller, summary
    Optional: agent_name, customer_name, customer_number, customer_email, concerns[], tasks[]
    """
    if request.method == "OPTIONS":
        return ("", 204)

    try:
        data = request.get_json(force=True) or {}
    except Exception as e:
        return jsonify({"error": "invalid json", "details": str(e)}), 400

    admin_tenant = (data.get("admin_tenant") or "").strip()
    forward_number = (data.get("forward_number") or "").strip()

    ok, auth_or_tenant = _require_v2_auth(admin_tenant)
    if not ok:
        msg, code = auth_or_tenant
        return jsonify({"error": msg}), code

    if not admin_tenant or not forward_number:
        return jsonify({"error": "admin_tenant and forward_number required"}), 400

    caller = data.get("caller", "")
    summary = data.get("summary", "")

    if not caller or not summary:
        return jsonify({"error": "caller and summary required"}), 400

    call_id = str(uuid.uuid4())
    now = datetime.utcnow()
    expires_at = int(now.timestamp()) + V2_TTL_SECONDS

    call_data = {
        "agent_name": data.get("agent_name", "AI Assistant"),
        "customer_name": data.get("customer_name", "—"),
        "customer_number": data.get("customer_number", caller or "—"),
        "customer_email": data.get("customer_email", "—"),
        "concerns": data.get("concerns", []) or [],
        "tasks": data.get("tasks", []) or []
    }

    payload = {
        "call_id": call_id,
        "caller": caller,
        "summary": summary,
        "call_data": call_data,
        "timestamp": now.isoformat() + "Z",
        "expires_at": expires_at,
        "admin_tenant": admin_tenant,
        "forward_number": forward_number
    }

    bucket_key = (admin_tenant, forward_number)
    V2_PENDING.setdefault(bucket_key, {})[call_id] = payload
    V2_CALL_INDEX[call_id] = bucket_key

    # Emit to the shared queue/number room; agents will pick up
    socketio.emit("incoming_call", {
        "call_id": call_id,
        "caller": caller,
        "target_id": forward_number,
        "target_type": "v2",
        "show_summary": False,
        "call_data": None,
        "summary": None,
        "version": "v2",
        "admin_tenant": admin_tenant,
        "forward_number": forward_number
    }, room=_v2_room(admin_tenant, forward_number))

    return jsonify({"ok": True, "call_id": call_id})

@app.route("/api/webhooks/v1/group_membership", methods=["POST"])
def webhook_v1_group_membership():
    """
    Webhook to register/refresh group membership mapping for V1.
    Body: {group_id: "<webex_uid>", members: ["<user_uid>", ...]}
    """
    data = request.get_json(force=True) or {}
    group_id = (data.get("group_id") or "").strip()
    members = data.get("members") or []
    if not group_id:
        return jsonify({"error": "group_id required"}), 400
    if not isinstance(members, list):
        return jsonify({"error": "members must be an array"}), 400

    GROUP_MEMBERS[group_id] = set([m for m in members if isinstance(m, str) and m.strip()])
    return jsonify({"ok": True, "group_id": group_id, "members_count": len(GROUP_MEMBERS[group_id])})

@app.route("/api/webhooks/v2/user_mapping", methods=["POST"])
def webhook_v2_user_mapping():
    """
    Webhook to map a Webex user to an admin tenant and forward numbers (queues/person DNs).
    Body: {user_id, admin_tenant, forward_numbers:[...]}
    """
    data = request.get_json(force=True) or {}
    user_id = (data.get("user_id") or "").strip()
    admin_tenant = (data.get("admin_tenant") or "").strip()
    forward_numbers = data.get("forward_numbers") or []
    if not user_id or not admin_tenant:
        return jsonify({"error": "user_id and admin_tenant required"}), 400
    if not isinstance(forward_numbers, list):
        return jsonify({"error": "forward_numbers must be an array"}), 400

    USER_TENANT[user_id] = admin_tenant
    USER_FORWARD_NUMBERS[user_id] = set([n for n in forward_numbers if isinstance(n, str) and n.strip()])
    return jsonify({"ok": True, "user_id": user_id, "admin_tenant": admin_tenant, "forward_numbers_count": len(USER_FORWARD_NUMBERS[user_id])})

@app.route("/api/webhooks/v2/call_answered", methods=["POST"])
def webhook_v2_call_answered():
    """
    Webhook to assign a V2 pending call to the actual answering user (telephony truth source).
    Body can be either:
      A) {call_id, user_id}
      B) {admin_tenant, forward_number, user_id}  (assigns the oldest pending call for that key)
    """
    data = request.get_json(force=True) or {}
    user_id = (data.get("user_id") or "").strip()
    call_id = (data.get("call_id") or "").strip()
    admin_tenant = (data.get("admin_tenant") or "").strip()
    forward_number = (data.get("forward_number") or "").strip()

    if not user_id:
        return jsonify({"error": "user_id required"}), 400

    # Resolve call_id if not provided (oldest pending in bucket)
    if not call_id:
        if not admin_tenant or not forward_number:
            return jsonify({"error": "call_id OR (admin_tenant and forward_number) required"}), 400
        bucket = V2_PENDING.get((admin_tenant, forward_number), {})
        if not bucket:
            return jsonify({"error": "no pending calls for bucket"}), 404
        # oldest by timestamp
        call_id = sorted(bucket.keys(), key=lambda cid: bucket[cid].get("timestamp", ""))[0]

    # Use the same assignment logic as pickup_call(v2), but driven by webhook
    key = V2_CALL_INDEX.get(call_id)
    if not key:
        return jsonify({"error": "call not found (index)", "call_id": call_id}), 404

    admin_tenant, forward_number = key
    bucket = V2_PENDING.get((admin_tenant, forward_number), {})
    call_info = bucket.get(call_id)
    if not call_info:
        return jsonify({"error": "call not pending", "call_id": call_id}), 404

    V2_ACTIVE_CALLS[call_id] = {
        "assigned_to": user_id,
        "admin_tenant": admin_tenant,
        "forward_number": forward_number,
        "created": datetime.utcnow().isoformat() + "Z"
    }
    bucket.pop(call_id, None)
    if not bucket:
        V2_PENDING.pop((admin_tenant, forward_number), None)
    V2_CALL_INDEX.pop(call_id, None)

    socketio.emit("call_assigned", {
        "call_id": call_id,
        "caller": call_info.get("caller", ""),
        "show_summary": True,
        "call_data": call_info.get("call_data"),
        "summary": call_info.get("summary"),
        "version": "v2",
        "admin_tenant": admin_tenant,
        "forward_number": forward_number,
        "assigned_via": "webhook"
    }, room=user_id)

    socketio.emit("call_removed", {"call_id": call_id, "version": "v2"}, room=_v2_room(admin_tenant, forward_number))

    HISTORY.setdefault(user_id, []).insert(0, {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": "v2",
        "direction": "inbound",
        "caller": call_info.get("caller", ""),
        "forward_number": forward_number,
        "summary": call_info.get("summary", ""),
        "call_id": call_id
    })

    return jsonify({"ok": True, "call_id": call_id, "assigned_to": user_id})

@app.route("/api/webhooks/history", methods=["POST"])
def webhook_history_event():
    """
    Generic history webhook to populate the History panel without relying on SDK.
    Body: {user_id, version, direction, caller, forward_number?, summary?, call_id?, timestamp?}
    """
    data = request.get_json(force=True) or {}
    user_id = (data.get("user_id") or "").strip()
    if not user_id:
        return jsonify({"error": "user_id required"}), 400

    event = {
        "timestamp": (data.get("timestamp") or datetime.utcnow().isoformat() + "Z"),
        "version": (data.get("version") or "unknown"),
        "direction": (data.get("direction") or "inbound"),
        "caller": (data.get("caller") or ""),
        "forward_number": data.get("forward_number"),
        "summary": data.get("summary", ""),
        "call_id": data.get("call_id")
    }
    HISTORY.setdefault(user_id, []).insert(0, event)
    return jsonify({"ok": True})

@app.route("/api/history", methods=["GET"])
def api_history():
    """Return history for the current user (populated via webhook + assignments)."""
    user_id = (request.args.get("user_id") or "").strip()
    if not user_id:
        return jsonify({"error": "user_id required"}), 400
    version = (request.args.get("version") or "all").lower()

    items = HISTORY.get(user_id, [])
    if version != "all":
        items = [x for x in items if (x.get("version") or "").lower() == version]
    # cap for safety
    return jsonify({"user_id": user_id, "items": items[:200]})

def _v2_cleanup_expired():
    """Delete expired V2 pending payloads (security)."""
    try:
        now_ts = int(datetime.utcnow().timestamp())
        expired = []
        for (tenant, fwd), bucket in list(V2_PENDING.items()):
            for cid, payload in list(bucket.items()):
                if int(payload.get("expires_at") or 0) <= now_ts:
                    expired.append((tenant, fwd, cid))

        for tenant, fwd, cid in expired:
            # Remove from pending stores
            b = V2_PENDING.get((tenant, fwd), {})
            b.pop(cid, None)
            V2_CALL_INDEX.pop(cid, None)
            if not b:
                V2_PENDING.pop((tenant, fwd), None)

            # Tell all listeners to remove this pending call from UI
            try:
                socketio.emit(
                    "call_removed",
                    {"call_id": cid, "version": "v2", "reason": "expired"},
                    room=_v2_room(tenant, fwd),
                )
            except Exception:
                pass

        if expired:
            print(f"[V2] Cleanup expired pending calls: {len(expired)}")
    except Exception as e:
        print(f"[V2] Cleanup error: {e}")



def _v2_cleanup_loop():
    """Background loop to periodically delete expired V2 pending payloads."""
    while True:
        _v2_cleanup_expired()
        # sleep in SocketIO-friendly way
        socketio.sleep(30)


_v2_bg_started = False

@app.before_first_request
def _start_background_tasks():
    global _v2_bg_started
    if _v2_bg_started:
        return
    _v2_bg_started = True
    socketio.start_background_task(_v2_cleanup_loop)



@app.route("/api/pending_calls/<user_id>")
def get_pending_calls(user_id):
    """Get pending calls for a user or group"""
    calls = PENDING_CALLS.get(user_id, [])
    return jsonify({"calls": calls})

# ========== END AUTHORIZATION ==========

@app.route("/simulate", methods=["POST"])
def simulate():
    """
    Accepts events from the Webex bridge (or your simulator):
      {event, call_id, caller, transcript, recording_url?, user_id}
    """
    data = request.get_json(force=True)
    if not data or "event" not in data:
        return jsonify({"error": "bad request"}), 400

    call_id   = data.get("call_id") or str(uuid.uuid4())
    caller    = (data.get("remoteNumber") or data.get("caller") or "unknown").strip()
    display_name = (data.get("displayName") or "").strip()
    user_id   = data.get("user_id")  # User who's in the call

    state     = (data.get("event") or "unknown").lower()
    transcript= data.get("transcript", "")
    rec_url   = data.get("recording_url")  # optional, if you wire webhooks later

    print(f"[simulate] Call state: {state}, caller: {caller}, displayName: {display_name}, user_id: {user_id}")

    entry = CALL_LOGS.setdefault(call_id, {
        "caller": caller,
        "created": datetime.utcnow().isoformat() + "Z",
        "events": []
    })

    if caller:
        entry["caller"] = caller
        if caller.lower() != "unknown":
            LAST_ACTIVE_BY_NUMBER[caller] = call_id

    if rec_url:
        entry["recording_url"] = rec_url

    entry["events"].append({
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "state": state,
        "transcript": transcript
    })

    # Emit to specific user's room if user_id provided, otherwise broadcast
    emit_target = user_id if user_id else None
    print(f"[simulate] Emitting call_event to: {emit_target or 'ALL'}")

    socketio.emit("call_event", {
        "call_id": call_id,
        "caller": entry["caller"],
        "remoteNumber": caller,
        "displayName": display_name,
        "state": state,
        "transcript": transcript
    }, room=emit_target)

    # on end: persist locally
    if state == "ended":
        _persist_call_assets(call_id, entry)
        final_text = "\n".join([e["transcript"] for e in entry["events"] if e.get("transcript")])
        if final_text.strip():
            _post_final_to_simulator(entry.get("caller","unknown"), final_text)

    return jsonify({"ok": True, "call_id": call_id})

def _post_final_to_simulator(number: str, text: str):
    base = SIMULATOR_BASE
    if not base: return
    try:
        requests.post(f"{base}/transcripts", json={"number": number, "text": text}, timeout=10)
    except Exception:
        pass

def _persist_call_assets(call_id: str, entry: dict):
    # file name like: +49221xxxxxx_<shortId>_2025-10-28.json
    caller = (entry.get("caller") or "unknown").replace(" ", "")
    short  = call_id[:8]
    stamp  = datetime.utcnow().strftime("%Y-%m-%d")
    base   = f"{caller}_{short}_{stamp}"

    # transcript JSON and text
    json_path = os.path.join(TRANS_DIR, base + ".json")
    txt_path  = os.path.join(TRANS_DIR, base + ".txt")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(entry, f, ensure_ascii=False, indent=2)
    # simple linearized transcript
    lines = []
    for e in entry["events"]:
        if e.get("transcript"):
            lines.append(f"[{e['timestamp']}] {e['transcript']}")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    # optional audio save if a local file path or downloadable URL is present
    rec_url = entry.get("recording_url")
    if rec_url and rec_url.startswith("file://"):
        src = rec_url.replace("file://", "")
        try:
            shutil.copy(src, os.path.join(AUDIO_DIR, base + os.path.splitext(src)[1]))
        except Exception:
            pass
    # If you later fetch from Webex API, do it here (requires WEBEX_TOKEN). See:
    # https://developer.webex.com/docs/api/v1/recordings/get-a-recording-transcript

@app.route("/calls", methods=["GET"])
def list_calls():
    return jsonify(list(CALL_LOGS.keys()))

@app.route("/calls/<call_id>", methods=["GET"])
def get_call(call_id):
    data = CALL_LOGS.get(call_id)
    if not data:
        return jsonify({"error": "not found"}), 404
    return jsonify(data)

@app.route("/assets/<call_id>", methods=["GET"])
def assets(call_id):
    if call_id not in CALL_LOGS:
        return jsonify({"error": "not found"}), 404
    post = CALL_LOGS[call_id].get("postcall", {})
    return jsonify({
        "recording_path": post.get("recording_path"),
        "recording_url": post.get("recording_url"),
        "transcript": post.get("transcript"),
        "summary": post.get("summary"),
    })


# quiet favicon warnings
@app.route("/favicon.ico")
def favicon():
    return ("", 204)
# 1) Webhook/ingest for a finished call to attach a recording file (or a ready transcript)
#    You can call this from: a webhook worker, an admin tool, or curl.
#    Accepts either: multipart form with 'file' (audio) OR JSON with 'recording_url' or 'transcript_text'.
@app.route("/ingest", methods=["POST"])
def ingest():
    # Identify which call to attach this to
    call_id = request.args.get("call_id") or (request.form.get("call_id") if request.form else None)
    if not call_id:
        try:
            call_id = (request.get_json(silent=True) or {}).get("call_id")
        except Exception:
            call_id = None
    if not call_id or call_id not in CALL_LOGS:
        return jsonify({"error": "unknown call_id"}), 400

    entry = CALL_LOGS[call_id]
    caller = entry.get("caller", "unknown")
    caller_dir = REC_DIR / secure_filename(caller)
    caller_dir.mkdir(parents=True, exist_ok=True)

    # Case A: direct transcript provided (e.g., future API gives you text)
    j = request.get_json(silent=True)
    if j and j.get("transcript_text"):
        text = j["transcript_text"]
        entry.setdefault("postcall", {})["transcript"] = text
        entry["postcall"]["summary"] = summarize_text(text)
        return jsonify({"ok": True, "stored": "transcript"}), 200

    # Case B: file upload (audio)
    if "file" in request.files:
        f = request.files["file"]
        if not f.filename:
            return jsonify({"error": "empty filename"}), 400
        ext = pathlib.Path(f.filename).suffix or ".wav"
        audio_path = caller_dir / f"{call_id}{ext}"
        f.save(audio_path)

        # Transcribe (stub for now; swap later with real ASR)
        text = transcribe_file(str(audio_path), lang_hint=None)
        entry.setdefault("postcall", {})["recording_path"] = str(audio_path)
        entry["postcall"]["transcript"] = text
        entry["postcall"]["summary"] = summarize_text(text)
        return jsonify({"ok": True, "stored": "audio+transcript"}), 200

    # Case C: JSON with a recording URL — you can download it server-side then transcribe
    if j and j.get("recording_url"):
        # TODO: download the URL to audio_path then call transcribe_file(audio_path)
        # For now, just acknowledge.
        entry.setdefault("postcall", {})["recording_url"] = j["recording_url"]
        return jsonify({"ok": True, "stored": "recording_url_placeholder"}), 200

    return jsonify({"error": "nothing ingested"}), 400

@app.route("/api/calls/history")
def api_calls_history():
    """Get call history for current user"""
    try:
        bearer = _bearer()
        print(f"[api_calls_history] Using bearer token: {bearer[:20]}...")

        # Try to get call history
        r = requests.get(
            f"{WEBEX_BASE_API}/telephony/calls/history",
            headers={"Authorization": f"Bearer {bearer}"},
            params={"max": 100},
            timeout=10,
        )

        print(f"[api_calls_history] Response: {r.status_code}")

        if r.status_code == 503:
            print(f"[api_calls_history] 503 error - endpoint might not be available")
            # Return empty list instead of error
            return jsonify({"items": []}), 200

        if not r.ok:
            print(f"[api_calls_history] Error: {r.text[:200]}")

        return (r.text, r.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        print(f"[api_calls_history] Exception: {e}")
        # Return empty list instead of crashing
        return jsonify({"items": []}), 200

@app.route("/api/cdr_feed")
def api_cdr_feed():
    r = requests.get(
        f"{WEBEX_BASE}/v1/reports/detailed-call-history/cdr_feed",
        headers={"Authorization": f"Bearer {_bearer()}"},
        timeout=20,
    )
    return (r.text, r.status_code, {"Content-Type": "application/json"})

def _wbx_headers(extra=None):
    if not _bearer():
        raise RuntimeError("Set WEBEX_BEARER env var with admin/compliance token")
    h = {"Authorization": f"Bearer {_bearer()}"}
    if extra: h.update(extra)
    return h

@app.get("/api/recordings/search")
def recordings_search():
    """
    Query Converged Recordings as Admin/Compliance and (optionally) filter by callSessionId.
    GET /api/recordings/search?sessionId=UUID&from=2025-10-28T00:00:00Z&to=2025-10-29T23:59:59Z
    """
    session_id = request.args.get("sessionId")
    params = {}
    if request.args.get("from"): params["from"] = request.args["from"]
    if request.args.get("to"):   params["to"]   = request.args["to"]

    r = requests.get(f"{WEBEX_BASE_API}/converged/recordings/admin/list",
                     headers=_wbx_headers({"timezone": "UTC"}), params=params, timeout=20)
    r.raise_for_status()
    items = r.json().get("items", [])
    if session_id:
        items = [x for x in items if x.get("serviceData", {}).get("callSessionId") == session_id]
    return jsonify({"items": items})

@app.get("/api/calls/recordings")
def list_recordings_by_session():
    session_id = request.args.get("sessionId")
    if not session_id:
        return jsonify({"items":[]}), 200
    # Converged Recordings supports filtering by callSessionId via query "callSessionId"
    r = requests.get(f"{WEBEX_BASE_API}/converged/recordings",
                     params={"callSessionId": session_id},
                     headers=_bearer(), timeout=20)
    return (r.text, r.status_code, {"Content-Type":"application/json"})

@app.get("/api/recordings/<rec_id>")
def recordings_details(rec_id):
    r = requests.get(f"{WEBEX_BASE_API}/converged/recordings/{rec_id}",
                     headers=_bearer(), timeout=20)
    return (r.text, r.status_code, {"Content-Type": "application/json"})

@app.get("/api/recordings/<rec_id>/download")
def recordings_download(rec_id):
    # proxy the temporary direct link so the browser can save/play
    info = requests.get(f"{WEBEX_BASE_API}/converged/recordings/{rec_id}",
                        headers=_bearer(), timeout=20).json()
    url = (info.get("temporaryDirectDownloadLinks") or {}).get("audioDownloadLink")
    if not url:
        return jsonify({"error": "no audioDownloadLink"}), 404
    blob = requests.get(url, timeout=120)
    blob.raise_for_status()
    return app.response_class(
        blob.content, mimetype="audio/mpeg",
        headers={"Content-Disposition": f'attachment; filename="{rec_id}.mp3"'}
    )

@app.post("/api/recordings/<rec_id>/transcribe")
def recordings_transcribe(rec_id):
    # fetch audio -> save -> transcribe -> summarize -> return text
    info = requests.get(f"{WEBEX_BASE_API}/converged/recordings/{rec_id}",
                        headers=_bearer(), timeout=20).json()
    url = (info.get("temporaryDirectDownloadLinks") or {}).get("audioDownloadLink")
    if not url:
        return jsonify({"error": "no audioDownloadLink"}), 404
    audio = requests.get(url, timeout=120)
    audio.raise_for_status()

    os.makedirs("data", exist_ok=True)
    audio_path = os.path.join("data", f"{rec_id}.mp3")
    with open(audio_path, "wb") as f:
        f.write(audio.content)

    text = transcribe_file(audio_path)       # your stub/real ASR
    summary = summarize_text(text)           # your stub/real summary
    return jsonify({"text": text, "summary": summary})

@app.get("/api/people/lookup")
def people_lookup():
    number = request.args.get("number", "").strip()
    if not number: return jsonify({}), 400
    r = requests.get(f"{WEBEX_BASE_API}/people",
                     params={"phoneNumber": number},
                     headers={"Authorization": f"Bearer {_bearer()}"},
                     timeout=10)
    return (r.text, r.status_code, {"Content-Type":"application/json"})

@app.post("/api/live/transcript")
def api_live_transcript():
    """
    Body: { "number": "+49...", "text": "..." }
    Emits a call_event so the Live panel shows it immediately, creating a call_id if needed.
    """
    j = request.get_json(force=True)
    number = (j.get("number") or "").strip()
    text   = (j.get("text")   or "").strip()
    if not number or not text:
        return jsonify({"error":"number and text required"}), 400

    call_id = LAST_ACTIVE_BY_NUMBER.get(number)
    if not call_id:
        # synthesize a pseudo-call so UI has somewhere to render
        call_id = str(uuid.uuid4())
        CALL_LOGS.setdefault(call_id, {
            "caller": number,
            "created": datetime.utcnow().isoformat()+"Z",
            "events": []
        })
        LAST_ACTIVE_BY_NUMBER[number] = call_id

    CALL_LOGS[call_id]["events"].append({
        "timestamp": datetime.utcnow().isoformat()+"Z",
        "state": "connected",
        "transcript": text
    })
    socketio.emit("call_event", {
        "call_id": call_id, "caller": number, "state": "connected", "transcript": text
    })
    return jsonify({"ok": True, "call_id": call_id})


if __name__ == "__main__":
    # Periodic V2 cleanup (in-memory TTL eviction). Runs every 60 seconds.
    import threading
    def _schedule_cleanup():
        _v2_cleanup_expired()
        threading.Timer(60, _schedule_cleanup).start()
    _schedule_cleanup()

    socketio.run(app, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)

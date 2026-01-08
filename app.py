# app.py — SPA with Live/History tabs, Socket.IO, and local saving on call end
from __future__ import annotations

import json
import os
import pathlib
import shutil
import uuid
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, redirect, render_template, request
from flask_socketio import SocketIO
from werkzeug.utils import secure_filename

from summarize import summarize_text
from transcribe import transcribe_file
from placetelAIMiddleWare import PlacetelAIMiddleware

WEBEX_BASE = "https://webexapis.com"
WEBEX_BASE_API = "https://webexapis.com/v1"

##### -------- TO MODIFY EVERY LOG IN ----------------------
WEBEX_BEARER = os.environ.get(
    "WEBEX_BEARER",
    "ZWM2OTZkMTgtZjg2MS00ZmQ5LTg4NzItYTk4YTE2MjE5Nzc0YmQ1N2ViYjUtZDA0_PE93_43fc283b-bec8-41ed-87dd-6050b49fb6ba",
)
SIMULATOR_BASE = os.environ.get("SIM_BASE", "").rstrip("/")  # e.g. https://<sim-ngrok>.ngrok-free.app
PLACETEL_SECRET_KEY = os.environ.get("PLACETEL_SECRET_KEY", "CHANGE_ME_16CHAR")
PLACETEL_SECRET_KEYS = os.environ.get("PLACETEL_SECRET_KEYS", "").strip()
##### ------------------------------------------------------

LAST_ACTIVE_BY_NUMBER: dict[str, str] = {}  # { "+4922...": "call_id" }
DATA_DIR = pathlib.Path("data")
REC_DIR = DATA_DIR / "recordings"
TRANS_DIR = DATA_DIR / "transcripts"
AUDIO_DIR = DATA_DIR / "audio"
AUTH_DIR = DATA_DIR / "auth"
AUTH_V2_DIR = DATA_DIR / "auth_v2"
WEBHOOK_DIR = DATA_DIR / "webhooks"
HISTORY_PATH = WEBHOOK_DIR / "call_history.json"
GROUPS_PATH = WEBHOOK_DIR / "group_members.json"
USER_ADMIN_PATH = WEBHOOK_DIR / "user_admin.json"

for path in (REC_DIR, TRANS_DIR, AUDIO_DIR, AUTH_DIR, AUTH_V2_DIR, WEBHOOK_DIR):
    path.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# in-memory store; persisted on call end
CALL_LOGS: dict[str, dict] = {}  # {call_id: {caller, created, events:[{timestamp,state,transcript}], recording_url?}}
AUTH_TOKENS: dict[str, dict] = {}
AUTH_V2: dict[str, dict] = {}

GROUP_MEMBERS: dict[str, set[str]] = {}
USER_ADMIN: dict[str, str] = {}
CALL_HISTORY: list[dict] = []

V2_ASSIGNMENTS: dict[str, dict] = {}  # forward_number -> {user_id, call_id, assigned_at}


MIDDLEWARE = PlacetelAIMiddleware(ttl_minutes=30)


def _read_json(path: pathlib.Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def _write_json(path: pathlib.Path, payload) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


# Load AUTH_TOKENS from disk on startup
print("[STARTUP] Loading auth tokens from disk...")
for auth_file in AUTH_DIR.glob("*.json"):
    try:
        auth_data = json.loads(auth_file.read_text(encoding="utf-8"))
        token = auth_data["target_id"]
        AUTH_TOKENS[token] = auth_data
    except Exception as exc:
        print(f"[STARTUP] Error loading {auth_file}: {exc}")
print(f"[STARTUP] Loaded {len(AUTH_TOKENS)} auth tokens from disk")

print("[STARTUP] Loading V2 auth tokens from disk...")
for auth_file in AUTH_V2_DIR.glob("*.json"):
    try:
        auth_data = json.loads(auth_file.read_text(encoding="utf-8"))
        token = auth_data["target_id"]
        AUTH_V2[token] = auth_data
    except Exception as exc:
        print(f"[STARTUP] Error loading {auth_file}: {exc}")
print(f"[STARTUP] Loaded {len(AUTH_V2)} V2 auth tokens from disk")

GROUP_MEMBERS_RAW = _read_json(GROUPS_PATH, {})
GROUP_MEMBERS = {k: set(v) for k, v in GROUP_MEMBERS_RAW.items()}
USER_ADMIN = _read_json(USER_ADMIN_PATH, {})
CALL_HISTORY = _read_json(HISTORY_PATH, [])


# Socket.IO event handlers
@socketio.on("connect")
def handle_connect():
    print(f"Client connected: {request.sid}")


@socketio.on("disconnect")
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")


@socketio.on("join")
def handle_join(data):
    from flask_socketio import join_room

    user_id = (data or {}).get("user_id")
    group_ids = (data or {}).get("group_ids") or []

    if user_id:
        join_room(user_id)
        print(f"User {user_id} joined room")

    # allow joining multiple group rooms
    for gid in group_ids:
        if gid and isinstance(gid, str):
            join_room(gid)
            print(f"User {user_id or request.sid} joined group room {gid}")


@socketio.on("leave")
def handle_leave(data):
    user_id = (data or {}).get("user_id")
    if user_id:
        from flask_socketio import leave_room

        leave_room(user_id)
        print(f"User {user_id} left room")


@app.after_request
def set_headers(resp):
    csp = "frame-ancestors 'self' https://*.webex.com https://*.webexcontent.com https://*.cisco.com"
    resp.headers["Content-Security-Policy"] = csp
    resp.headers.pop("X-Frame-Options", None)
    return resp


@app.route("/")
def index():
    return render_template("index.html")  # single-page app with Live/History tabs


@app.route("/live")
def live_view():
    return render_template("index.html")


@app.route("/history")
def history_view():
    return render_template("history.html")


@app.route("/authorization")
def authorization_view():
    return render_template("authorization.html")


@app.route("/webex_bridge.html")
def legacy_bridge():
    return redirect("/", code=302)


@app.route("/simulate", methods=["POST"])
def simulate():
    """
    Accepts events from the Webex bridge (or your simulator):
      {event, call_id, caller, transcript, recording_url?}
    """
    data = request.get_json(force=True)
    if not data or "event" not in data:
        return jsonify({"error": "bad request"}), 400

    call_id = data.get("call_id") or str(uuid.uuid4())
    caller = (data.get("remoteNumber") or data.get("caller") or "unknown").strip()
    display_name = (data.get("displayName") or "").strip()

    state = (data.get("event") or "unknown").lower()
    transcript = data.get("transcript", "")
    rec_url = data.get("recording_url")  # optional, if you wire webhooks later

    _record_call_event(
        call_id=call_id,
        caller=caller,
        state=state,
        transcript=transcript,
        remote_number=caller,
        display_name=display_name,
        recording_url=rec_url,
    )

    # on end: persist locally
    if state == "ended":
        entry = CALL_LOGS.get(call_id)
        if entry:
            _persist_call_assets(call_id, entry)
            final_text = "\n".join([e["transcript"] for e in entry["events"] if e.get("transcript")])
            if final_text.strip():
                _post_final_to_simulator(entry.get("caller", "unknown"), final_text)

    return jsonify({"ok": True, "call_id": call_id})


def _post_final_to_simulator(number: str, text: str):
    base = SIMULATOR_BASE
    if not base:
        return
    try:
        requests.post(f"{base}/transcripts", json={"number": number, "text": text}, timeout=10)
    except Exception:
        pass


def _persist_call_assets(call_id: str, entry: dict):
    # file name like: +49221xxxxxx_<shortId>_2025-10-28.json
    caller = (entry.get("caller") or "unknown").replace(" ", "")
    short = call_id[:8]
    stamp = datetime.utcnow().strftime("%Y-%m-%d")
    base = f"{caller}_{short}_{stamp}"

    # transcript JSON and text
    json_path = os.path.join(TRANS_DIR, base + ".json")
    txt_path = os.path.join(TRANS_DIR, base + ".txt")
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
    return jsonify(
        {
            "recording_path": post.get("recording_path"),
            "recording_url": post.get("recording_url"),
            "transcript": post.get("transcript"),
            "summary": post.get("summary"),
        }
    )


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


def _bearer():
    # for dev: valid for each 12h to modify each log in
    return os.environ.get(
        "WEBEX_USER_TOKEN",
        "ZWM2OTZkMTgtZjg2MS00ZmQ5LTg4NzItYTk4YTE2MjE5Nzc0YmQ1N2ViYjUtZDA0_PE93_43fc283b-bec8-41ed-87dd-6050b49fb6ba",
    )


def _record_call_event(
    *,
    call_id: str,
    caller: str,
    state: str,
    transcript: str,
    remote_number: str | None = None,
    display_name: str | None = None,
    recording_url: str | None = None,
    room: str | None = None,
):
    entry = CALL_LOGS.setdefault(
        call_id,
        {
            "caller": caller,
            "created": datetime.utcnow().isoformat() + "Z",
            "events": [],
        },
    )

    if caller:
        entry["caller"] = caller
        if caller.lower() != "unknown":
            LAST_ACTIVE_BY_NUMBER[caller] = call_id

    if recording_url:
        entry["recording_url"] = recording_url

    entry["events"].append(
        {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "state": state,
            "transcript": transcript,
        }
    )

    socketio.emit(
        "call_event",
        {
            "call_id": call_id,
            "caller": caller,
            "remoteNumber": remote_number or caller,
            "displayName": display_name or "",
            "state": state,
            "transcript": transcript,
        },
        room=room,
    )


def _emit_transcript_to_targets(targets: list[str], payload: dict, state: str = "connected"):
    transcript = payload.get("transcript") or payload.get("text") or ""
    caller = (payload.get("remoteNumber") or payload.get("caller") or payload.get("number") or "unknown").strip()
    call_id = payload.get("call_id") or str(uuid.uuid4())
    for target in targets:
        _record_call_event(
            call_id=call_id,
            caller=caller,
            state=state,
            transcript=transcript,
            remote_number=payload.get("remoteNumber") or payload.get("number") or caller,
            display_name=payload.get("displayName") or payload.get("display_name") or "",
            room=target,
        )


def _v2_expected_token(admin_tenant: str) -> str:
    return f"{PLACETEL_SECRET_KEY}{admin_tenant}" if admin_tenant else ""


def _allowed_secret_keys() -> list[str]:
    if PLACETEL_SECRET_KEYS:
        return [k.strip() for k in PLACETEL_SECRET_KEYS.split(",") if k.strip()]
    return [PLACETEL_SECRET_KEY]


def _match_secret_key(token: str, admin_tenant: str) -> bool:
    if not admin_tenant or not token:
        return False
    for secret in _allowed_secret_keys():
        if len(secret) != 16:
            continue
        if token == f"{secret}{admin_tenant}":
            return True
    return False


def _require_v2_bearer(admin_tenant: str):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return False
    token = auth_header.split(" ", 1)[1].strip()
    return _match_secret_key(token, admin_tenant)


@app.route("/api/calls/history")
def api_calls_history():
    # Webhook-fed history store
    return jsonify({"items": CALL_HISTORY})


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
    if extra:
        h.update(extra)
    return h


@app.get("/api/recordings/search")
def recordings_search():
    """
    Query Converged Recordings as Admin/Compliance and (optionally) filter by callSessionId.
    GET /api/recordings/search?sessionId=UUID&from=2025-10-28T00:00:00Z&to=2025-10-29T23:59:59Z
    """
    session_id = request.args.get("sessionId")
    params = {}
    if request.args.get("from"):
        params["from"] = request.args["from"]
    if request.args.get("to"):
        params["to"] = request.args["to"]

    r = requests.get(
        f"{WEBEX_BASE_API}/converged/recordings/admin/list",
        headers=_wbx_headers({"timezone": "UTC"}),
        params=params,
        timeout=20,
    )
    r.raise_for_status()
    items = r.json().get("items", [])
    if session_id:
        items = [x for x in items if x.get("serviceData", {}).get("callSessionId") == session_id]
    return jsonify({"items": items})


@app.get("/api/calls/recordings")
def list_recordings_by_session():
    session_id = request.args.get("sessionId")
    if not session_id:
        return jsonify({"items": []}), 200
    # Converged Recordings supports filtering by callSessionId via query "callSessionId"
    r = requests.get(
        f"{WEBEX_BASE_API}/converged/recordings",
        params={"callSessionId": session_id},
        headers={"Authorization": f"Bearer {_bearer()}"},
        timeout=20,
    )
    return (r.text, r.status_code, {"Content-Type": "application/json"})


@app.get("/api/recordings/<rec_id>")
def recordings_details(rec_id):
    r = requests.get(
        f"{WEBEX_BASE_API}/converged/recordings/{rec_id}",
        headers={"Authorization": f"Bearer {_bearer()}"},
        timeout=20,
    )
    return (r.text, r.status_code, {"Content-Type": "application/json"})


@app.get("/api/recordings/<rec_id>/download")
def recordings_download(rec_id):
    # proxy the temporary direct link so the browser can save/play
    info = requests.get(
        f"{WEBEX_BASE_API}/converged/recordings/{rec_id}",
        headers={"Authorization": f"Bearer {_bearer()}"},
        timeout=20,
    ).json()
    url = (info.get("temporaryDirectDownloadLinks") or {}).get("audioDownloadLink")
    if not url:
        return jsonify({"error": "no audioDownloadLink"}), 404
    blob = requests.get(url, timeout=120)
    blob.raise_for_status()
    return app.response_class(
        blob.content,
        mimetype="audio/mpeg",
        headers={"Content-Disposition": f'attachment; filename="{rec_id}.mp3"'},
    )


@app.post("/api/recordings/<rec_id>/transcribe")
def recordings_transcribe(rec_id):
    # fetch audio -> save -> transcribe -> summarize -> return text
    info = requests.get(
        f"{WEBEX_BASE_API}/converged/recordings/{rec_id}",
        headers={"Authorization": f"Bearer {_bearer()}"},
        timeout=20,
    ).json()
    url = (info.get("temporaryDirectDownloadLinks") or {}).get("audioDownloadLink")
    if not url:
        return jsonify({"error": "no audioDownloadLink"}), 404
    audio = requests.get(url, timeout=120)
    audio.raise_for_status()

    os.makedirs("data", exist_ok=True)
    audio_path = os.path.join("data", f"{rec_id}.mp3")
    with open(audio_path, "wb") as f:
        f.write(audio.content)

    text = transcribe_file(audio_path)  # your stub/real ASR
    summary = summarize_text(text)  # your stub/real summary
    return jsonify({"text": text, "summary": summary})


@app.get("/api/people/lookup")
def people_lookup():
    number = request.args.get("number", "").strip()
    if not number:
        return jsonify({}), 400
    r = requests.get(
        f"{WEBEX_BASE_API}/people",
        params={"phoneNumber": number},
        headers={"Authorization": f"Bearer {_bearer()}"},
        timeout=10,
    )
    return (r.text, r.status_code, {"Content-Type": "application/json"})


@app.post("/api/live/transcript")
def api_live_transcript():
    """
    Body: { "number": "+49...", "text": "..." }
    Emits a call_event so the Live panel shows it immediately, creating a call_id if needed.
    """
    j = request.get_json(force=True)
    number = (j.get("number") or "").strip()
    text = (j.get("text") or "").strip()
    if not number or not text:
        return jsonify({"error": "number and text required"}), 400

    call_id = LAST_ACTIVE_BY_NUMBER.get(number)
    if not call_id:
        call_id = str(uuid.uuid4())

    _record_call_event(
        call_id=call_id,
        caller=number,
        state="connected",
        transcript=text,
        remote_number=number,
        display_name=j.get("displayName") or "",
    )
    return jsonify({"ok": True, "call_id": call_id})


@app.post("/api/auth/generate")
def auth_generate():
    payload = request.get_json(force=True)
    target_id = (payload.get("target_id") or "").strip()
    target_type = (payload.get("target_type") or "user").strip()
    target_name = (payload.get("target_name") or "").strip()

    if not target_id:
        return jsonify({"error": "target_id required"}), 400

    auth_data = {
        "target_id": target_id,
        "target_type": target_type,
        "target_name": target_name,
        "version": "v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    AUTH_TOKENS[target_id] = auth_data
    _write_json(AUTH_DIR / f"{target_id}.json", auth_data)

    base = request.host_url.rstrip("/")
    post_url = f"{base}/api/post/{target_id}"
    return jsonify({"post_url": post_url, "version": "v1"})


@app.post("/api/auth/v2/generate")
def auth_generate_v2():
    payload = request.get_json(force=True)
    target_id = (payload.get("target_id") or "").strip()
    target_type = (payload.get("target_type") or "user").strip()
    target_name = (payload.get("target_name") or "").strip()
    admin_tenant = (payload.get("admin_tenant") or "").strip()

    if not target_id:
        return jsonify({"error": "target_id required"}), 400
    if not admin_tenant:
        return jsonify({"error": "admin_tenant required"}), 400

    auth_data = {
        "target_id": target_id,
        "target_type": target_type,
        "target_name": target_name,
        "admin_tenant": admin_tenant,
        "version": "v2",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    AUTH_V2[target_id] = auth_data
    _write_json(AUTH_V2_DIR / f"{target_id}.json", auth_data)

    USER_ADMIN[target_id] = admin_tenant
    _write_json(USER_ADMIN_PATH, USER_ADMIN)

    base = request.host_url.rstrip("/")
    post_url = f"{base}/api/placetel/v2/transcripts"
    return jsonify(
        {
            "post_url": post_url,
            "version": "v2",
            "bearer_hint": "Authorization: Bearer <SECRET_KEY><ADMIN_TENANT>",
        }
    )


@app.post("/api/post/<token>")
def post_transcript_v1(token: str):
    auth = AUTH_TOKENS.get(token)
    if not auth:
        return jsonify({"error": "invalid token"}), 403

    payload = request.get_json(force=True)
    target_type = auth.get("target_type", "user")
    targets = [auth["target_id"]]

    if target_type == "group":
        members = GROUP_MEMBERS.get(auth["target_id"], set())
        if members:
            targets = list(members)
        else:
            targets = [auth["target_id"]]

    _emit_transcript_to_targets(targets, payload)
    return jsonify({"ok": True, "version": "v1"})


@app.post("/api/placetel/v2/transcripts")
def placetel_v2_transcripts():
    payload = request.get_json(force=True)
    forward_number = (payload.get("forward_number") or "").strip()
    admin_tenant = (payload.get("admin_tenant") or "").strip()

    if not forward_number:
        return jsonify({"error": "forward_number required"}), 400
    if not admin_tenant:
        return jsonify({"error": "admin_tenant required"}), 400
    if not any(len(key) == 16 for key in _allowed_secret_keys()):
        return jsonify({"error": "PLACETEL_SECRET_KEY(S) must include a 16 character key"}), 500
    if not _require_v2_bearer(admin_tenant):
        return jsonify({"error": "invalid bearer"}), 403

    MIDDLEWARE.purge()

    assignment = V2_ASSIGNMENTS.get(forward_number)
    if assignment:
        payload["call_id"] = payload.get("call_id") or assignment.get("call_id")
        _emit_transcript_to_targets([assignment["user_id"]], payload)
        return jsonify({"ok": True, "delivered": True, "version": "v2"})

    call_id = MIDDLEWARE.add(payload, forward_number, admin_tenant)
    return jsonify({"ok": True, "stored": True, "call_id": call_id, "version": "v2"})


@app.post("/api/webhooks/groups/members")
def webhook_group_members():
    payload = request.get_json(force=True)
    group_id = (payload.get("group_id") or "").strip()
    members = payload.get("members") or []

    if not group_id:
        return jsonify({"error": "group_id required"}), 400

    GROUP_MEMBERS[group_id] = set(str(member) for member in members)
    _write_json(GROUPS_PATH, {k: sorted(v) for k, v in GROUP_MEMBERS.items()})
    return jsonify({"ok": True, "group_id": group_id, "members": sorted(GROUP_MEMBERS[group_id])})


@app.post("/api/webhooks/calls/assigned")
def webhook_call_assigned():
    payload = request.get_json(force=True)
    forward_number = (payload.get("forward_number") or "").strip()
    user_id = (payload.get("user_id") or "").strip()
    call_id = (payload.get("call_id") or "").strip() or None

    if not forward_number or not user_id:
        return jsonify({"error": "forward_number and user_id required"}), 400

    V2_ASSIGNMENTS[forward_number] = {
        "user_id": user_id,
        "call_id": call_id,
        "assigned_at": datetime.now(timezone.utc).isoformat(),
    }

    entry = MIDDLEWARE.pop_for_forward(forward_number, call_id)
    if entry:
        _emit_transcript_to_targets([user_id], entry["payload"])
        return jsonify({"ok": True, "delivered": True})
    return jsonify({"ok": True, "delivered": False})


@app.post("/api/webhooks/calls/history")
def webhook_calls_history():
    payload = request.get_json(force=True)
    items = payload.get("items") or []
    if payload.get("item"):
        items = [payload["item"]]

    if not isinstance(items, list) or not items:
        return jsonify({"error": "items required"}), 400

    for item in items:
        item.setdefault("received_at", datetime.now(timezone.utc).isoformat())
        CALL_HISTORY.append(item)

    _write_json(HISTORY_PATH, CALL_HISTORY)
    return jsonify({"ok": True, "count": len(items)})


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)

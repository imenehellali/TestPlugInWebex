# app.py — SPA with Live/History tabs, Socket.IO, and local saving on call end
import pathlib, json
from werkzeug.utils import secure_filename
from transcribe import transcribe_file
from summarize import summarize_text
from flask import Flask, redirect, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO
from datetime import datetime
import os, uuid, json, pathlib, shutil, io, requests

WEBEX_BASE = "https://webexapis.com"
WEBEX_BASE_API = "https://webexapis.com/v1"

##### -------- TO MODIFY EVERY LOG IN ----------------------
WEBEX_BEARER = os.environ.get("WEBEX_BEARER", "ZWM2OTZkMTgtZjg2MS00ZmQ5LTg4NzItYTk4YTE2MjE5Nzc0YmQ1N2ViYjUtZDA0_PE93_43fc283b-bec8-41ed-87dd-6050b49fb6ba")
SIMULATOR_BASE = os.environ.get("SIM_BASE", "").rstrip("/")  # e.g. https://<sim-ngrok>.ngrok-free.app
##### ------------------------------------------------------

LAST_ACTIVE_BY_NUMBER = {}  # { "+4922...": "call_id" }
BASE_DIR = "/Users/imenhellali/Desktop/TestPlugInWebex"  # explicit, as you asked
DATA_DIR = pathlib.Path("data")
REC_DIR = DATA_DIR / "recordings"
pathlib.Path(REC_DIR).mkdir(parents=True, exist_ok=True)
TRANS_DIR = DATA_DIR /"transcripts"
AUDIO_DIR = DATA_DIR /"audio"
pathlib.Path(TRANS_DIR).mkdir(parents=True, exist_ok=True)
pathlib.Path(AUDIO_DIR).mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# in-memory store; persisted on call end
CALL_LOGS = {}  # {call_id: {caller, created, events:[{timestamp,state,transcript}], recording_url?}}

@app.after_request
def set_headers(resp):
    csp = "frame-ancestors 'self' https://*.webex.com https://*.webexcontent.com https://*.cisco.com"
    resp.headers["Content-Security-Policy"] = csp
    resp.headers.pop("X-Frame-Options", None)
    return resp

@app.route("/")
def index():
    return render_template("index.html")  # single-page app with Live/History tabs

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

    call_id   = data.get("call_id") or str(uuid.uuid4())
    caller    = data.get("caller", "unknown")
    state     = (data.get("event") or "unknown").lower()
    transcript= data.get("transcript", "")
    rec_url   = data.get("recording_url")  # optional, if you wire webhooks later

    entry = CALL_LOGS.setdefault(call_id, {
        "caller": caller,
        "created": datetime.utcnow().isoformat() + "Z",
        "events": []
    })
    entry["caller"] = caller or entry["caller"]
    if caller and caller.lower() != "unknown":
        LAST_ACTIVE_BY_NUMBER[caller] = call_id
    if rec_url:
        entry["recording_url"] = rec_url

    ev = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "state": state,
        "transcript": transcript
    }
    entry["events"].append(ev)

    # push to live panel
    socketio.emit("call_event", {
        "call_id": call_id,
        "caller": entry["caller"],
        "state": state,
        "transcript": transcript
    })

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

def _bearer():
    # for dev: valid for each 12h to modify each log in
    return os.environ.get("WEBEX_USER_TOKEN", "ZWM2OTZkMTgtZjg2MS00ZmQ5LTg4NzItYTk4YTE2MjE5Nzc0YmQ1N2ViYjUtZDA0_PE93_43fc283b-bec8-41ed-87dd-6050b49fb6ba")

@app.route("/api/calls/history")
def api_calls_history():
    r = requests.get(
        f"{WEBEX_BASE}/v1/telephony/calls/history",
        headers={"Authorization": f"Bearer {_bearer()}"},
        timeout=10,
    )
    return (r.text, r.status_code, {"Content-Type": "application/json"})

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
    socketio.run(app, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)

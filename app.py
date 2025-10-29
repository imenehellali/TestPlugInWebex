# app.py — SPA with Live/History tabs, Socket.IO, and local saving on call end
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO
from datetime import datetime
import os, uuid, json, pathlib, shutil


BASE_DIR = "/Users/imenhellali/Desktop/TestPlugInWebex"  # explicit, as you asked
DATA_DIR = os.path.join(BASE_DIR, "data")
TRANS_DIR = os.path.join(DATA_DIR, "transcripts")
AUDIO_DIR = os.path.join(DATA_DIR, "audio")
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
def webex_bridge():
    return send_from_directory(BASE_DIR, "webex_bridge.html")

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
    }, broadcast=True)

    # on end: persist locally
    if state == "ended":
        _persist_call_assets(call_id, entry)

    return jsonify({"ok": True, "call_id": call_id})

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
    """Return expected local file names for this call."""
    data = CALL_LOGS.get(call_id)
    if not data: return jsonify({"error": "not found"}), 404
    caller = (data.get("caller") or "unknown").replace(" ", "")
    short  = call_id[:8]
    stamp  = datetime.utcnow().strftime("%Y-%m-%d")
    base   = f"{caller}_{short}_{stamp}"
    return jsonify({
        "transcript_json": f"data/transcripts/{base}.json",
        "transcript_txt":  f"data/transcripts/{base}.txt",
        "audio_maybe":     f"data/audio/{base}.*"
    })

# quiet favicon warnings
@app.route("/favicon.ico")
def favicon():
    return ("", 204)

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)

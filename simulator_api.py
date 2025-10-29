# simulator_api.py
# A tiny REST API that stores transcripts per number into an Excel file,
# can return the latest transcript, and can push a transcript to your app.

from flask import Flask, request, jsonify
import os, time, pathlib, requests
import pandas as pd
from datetime import datetime, timezone

DATA_DIR = pathlib.Path("sim_data")
DATA_DIR.mkdir(exist_ok=True)
XLSX_PATH = DATA_DIR / "transcripts.xlsx"

app = Flask(__name__)

def load_df():
    if XLSX_PATH.exists():
        return pd.read_excel(XLSX_PATH, index_col=0)
    return pd.DataFrame()

def save_df(df: pd.DataFrame):
    # index = phone number; columns = ISO timestamps; cell = transcript text
    with pd.ExcelWriter(XLSX_PATH, engine="openpyxl", mode="w") as w:
        df.to_excel(w)

def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

@app.post("/transcripts")
def add_transcript():
    """
    Body: { "number": "+4922197580971", "text": "..." }
    Adds a new column for this call instance (timestamped), returns column key.
    """
    j = request.get_json(force=True)
    number = (j.get("number") or "").strip()
    text   = (j.get("text")   or "").strip()
    if not number or not text:
        return jsonify({"error":"number and text required"}), 400

    df = load_df()
    col = now_iso()
    if number not in df.index:
        df.loc[number, col] = text
    else:
        df.loc[number, col] = text
    # fill NaNs with empty for nicer sheet
    df = df.fillna("")
    save_df(df)
    return jsonify({"ok": True, "column": col})

@app.get("/transcripts/<number>/latest")
def latest(number):
    df = load_df()
    if number not in df.index or df.loc[number].dropna().empty:
        return jsonify({"number": number, "text": ""})
    # pick the rightmost non-empty column
    row = df.loc[number]
    latest_col = [c for c in df.columns if isinstance(row.get(c, ""), str) and row.get(c, "").strip()]
    if not latest_col:
        return jsonify({"number": number, "text": ""})
    # df.columns is ordered; last is most recent
    col = latest_col[-1]
    return jsonify({"number": number, "text": str(row[col]), "column": col})

@app.post("/push-to-app")
def push_to_app():
    """
    Body: { "number": "...", "app_base": "https://<your-ngrok>.ngrok-free.app" }
    Loads the latest transcript for number and POSTs it to your app.
    """
    j = request.get_json(force=True)
    number = (j.get("number") or "").strip()
    app_base = (j.get("app_base") or "").rstrip("/")
    if not number or not app_base:
        return jsonify({"error":"number and app_base required"}), 400
    r = app.test_client().get(f"/transcripts/{number}/latest")
    payload = r.get_json()
    text = payload.get("text","")
    if not text:
        return jsonify({"error":"no transcript for number"}), 404
    # send to your app
    resp = requests.post(f"{app_base}/api/live/transcript",
                         json={"number": number, "text": text, "ts": now_iso()},
                         timeout=10)
    return jsonify({"app_status": resp.status_code, "app_text": resp.text})

@app.post("/bootstrap-example")
def bootstrap():
    """Generate example data for +4922197580971 with a few columns, keep only last when pushing."""
    number = "+4922197580971"
    df = load_df()
    samples = [
        "Hallo, ich habe Fragen zu meinem Konto.",
        "Können Sie mir beim Passwort helfen?",
        "Ich möchte ein Angebot besprechen."
    ]
    cols = []
    for s in samples:
        ts = now_iso()
        cols.append(ts)
        df.loc[number, ts] = s
        time.sleep(0.3)
    save_df(df.fillna(""))
    return jsonify({"ok": True, "number": number, "columns": cols})

if __name__ == "__main__":
    # Run on 7000, then:  ngrok http 7000
    app.run(host="0.0.0.0", port=7000)

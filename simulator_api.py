# simulator_api.py
# Simple API for storing and retrieving call transcripts during testing
# Run with: python simulator_api.py (will run on port 7000)

from flask import Flask, request, jsonify
import os, pathlib
from datetime import datetime

DATA_DIR = pathlib.Path("sim_data")
DATA_DIR.mkdir(exist_ok=True)

app = Flask(__name__)

# In-memory storage for transcripts
TRANSCRIPTS = {}  # {phone_number: [{timestamp, text, name}]}

@app.post("/transcripts")
def add_transcript():
    """
    Store a transcript for a phone number
    Body: {"number": "+4922197580971", "text": "...", "name": "Customer Name"}
    """
    data = request.get_json(force=True)
    number = (data.get("number") or "").strip()
    text = (data.get("text") or "").strip()
    name = (data.get("name") or "").strip()
    
    if not number or not text:
        return jsonify({"error": "number and text required"}), 400

    if number not in TRANSCRIPTS:
        TRANSCRIPTS[number] = []
    
    TRANSCRIPTS[number].append({
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "text": text,
        "name": name
    })
    
    return jsonify({"ok": True, "count": len(TRANSCRIPTS[number])})

@app.get("/transcripts/<number>/latest")
def get_latest(number):
    """Get the latest transcript for a phone number"""
    if number not in TRANSCRIPTS or not TRANSCRIPTS[number]:
        return jsonify({"number": number, "text": "", "name": ""})
    
    latest = TRANSCRIPTS[number][-1]
    return jsonify({
        "number": number,
        "text": latest["text"],
        "name": latest.get("name", ""),
        "timestamp": latest["timestamp"]
    })

@app.get("/transcripts/<number>/all")
def get_all(number):
    """Get all transcripts for a phone number"""
    transcripts = TRANSCRIPTS.get(number, [])
    return jsonify({"number": number, "transcripts": transcripts, "count": len(transcripts)})

@app.get("/transcripts")
def list_all():
    """List all phone numbers with transcripts"""
    return jsonify({
        "numbers": list(TRANSCRIPTS.keys()),
        "total": len(TRANSCRIPTS)
    })

@app.delete("/transcripts/<number>")
def delete_number(number):
    """Delete all transcripts for a phone number"""
    if number in TRANSCRIPTS:
        count = len(TRANSCRIPTS[number])
        del TRANSCRIPTS[number]
        return jsonify({"ok": True, "deleted": count})
    return jsonify({"ok": True, "deleted": 0})

@app.get("/")
def index():
    return jsonify({
        "name": "Simulator API",
        "version": "1.0",
        "endpoints": {
            "POST /transcripts": "Add a transcript",
            "GET /transcripts/<number>/latest": "Get latest transcript",
            "GET /transcripts/<number>/all": "Get all transcripts",
            "GET /transcripts": "List all numbers",
            "DELETE /transcripts/<number>": "Delete all transcripts for number"
        }
    })

if __name__ == "__main__":
    print("Starting Simulator API on http://localhost:7000")
    print("Use this for testing call transcript storage")
    app.run(host="0.0.0.0", port=7000, debug=True)

import os
from flask import Flask, render_template, request, jsonify
import requests
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

API_KEY = "cfdeaf310b0c41104bf5ebca007ee5abc6ec8dd6bcb97c88f33b7c45efb8c598"  # ← Your API key here

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan_url():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "No URL provided"}), 400

    url = data["url"]
    headers = {"x-apikey": API_KEY}

    try:
        # Submit URL to VirusTotal
        resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )
        if resp.status_code != 200:
            return jsonify({"error": "Error submitting URL", "details": resp.json()}), resp.status_code

        scan_id = resp.json()["data"]["id"]

        # Get analysis result
        analysis = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
            headers=headers
        )
        if analysis.status_code != 200:
            return jsonify({"error": "Error fetching analysis", "details": analysis.json()}), analysis.status_code

        return jsonify(analysis.json())

    except Exception as e:
        return jsonify({"error": "Internal server error", "message": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
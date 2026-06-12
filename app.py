from flask import Flask, render_template, request, jsonify, send_file
from analyzer import analyze_email
from database import (
    init_db,
    save_analysis,
    get_history,
    delete_all_history,
    get_risk_stats,
    get_daily_stats,
    delete_history_item
)
from pdf_generator import generate_pdf
from email import message_from_string, policy
from datetime import datetime, timezone
import sqlite3

# -----------------------------
# APP INIT
# -----------------------------
app = Flask(__name__)
init_db()

# -----------------------------
# HOME
# -----------------------------
@app.route("/")
def home():
    return render_template("index.html")


# -----------------------------
# CHART DATA
# -----------------------------
@app.route("/risk-chart")
def risk_chart():
    return jsonify(get_risk_stats())


@app.route("/daily-chart")
def daily_chart():
    return jsonify(get_daily_stats())


# -----------------------------
# TEXT ANALYSIS
# -----------------------------
@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json
    email_text = data.get("email", "")

    result = analyze_email(email_text)

    timestamp = datetime.now(timezone.utc).isoformat()

    save_analysis({
        "timestamp": timestamp,
        "risk_level": result["risk_level"],
        "risk_score": result["risk_score"],
        "sender": result.get("sender", ""),
        "subject": result.get("subject", ""),
        "url_count": len(result.get("urls_found", []))
    })

    return jsonify({"report": result})


# -----------------------------
# DELETE ALL HISTORY
# -----------------------------
@app.route("/delete-history", methods=["POST"])
def delete_history():
    delete_all_history()
    return jsonify({"message": "History hidden successfully"})


# -----------------------------
# FILE UPLOAD (.eml)
# -----------------------------
@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]

    if not file.filename.lower().endswith(".eml"):
        return jsonify({"error": "Only .eml files are supported"}), 400

    raw_email = file.read().decode("utf-8", errors="ignore")

    msg = message_from_string(raw_email, policy=policy.default)

    result = analyze_email(raw_email)

    timestamp = datetime.now(timezone.utc).isoformat()

    save_analysis({
        "timestamp": timestamp,
        "risk_level": result["risk_level"],
        "risk_score": result["risk_score"],
        "sender": result.get("sender", ""),
        "subject": result.get("subject", ""),
        "url_count": len(result.get("urls_found", []))
    })

    return jsonify({"report": result})


# -----------------------------
# HISTORY (VISIBLE ONLY)
# -----------------------------
@app.route("/history")
def history():
    rows = get_history()

    data = []
    for row in rows:
        data.append({
            "id": row[0],
            "timestamp": row[1],
            "risk_score": row[2],
            "risk_level": row[3],
            "sender": row[4],
            "subject": row[5],
            "url_count": row[6]
        })

    return jsonify(data)


# -----------------------------
# ALL HISTORY (ADMIN VIEW)
# -----------------------------
@app.route("/all-history")
def all_history():
    conn = sqlite3.connect("phishing_analyzer.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, timestamp, risk_score, risk_level,
               sender, subject, url_count, is_hidden
        FROM analyses
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    data = []
    for row in rows:
        data.append({
            "id": row[0],
            "timestamp": row[1],
            "risk_score": row[2],
            "risk_level": row[3],
            "sender": row[4],
            "subject": row[5],
            "url_count": row[6],
            "is_hidden": row[7]
        })

    return jsonify(data)


# -----------------------------
# DELETE SINGLE RECORD
# -----------------------------
@app.route("/delete-history/<int:record_id>", methods=["POST"])
def delete_history_item_route(record_id):
    delete_history_item(record_id)
    return jsonify({"message": "Record hidden successfully"})


# -----------------------------
# PDF DOWNLOAD
# -----------------------------
@app.route("/download-report", methods=["POST"])
def download_report():
    data = request.json
    report = data["report"]

    pdf_file = generate_pdf(report)

    return send_file(
        pdf_file,
        as_attachment=True,
        download_name="Phishing_Report.pdf"
    )


# -----------------------------
# RUN (FOR RENDER)
# -----------------------------
if __name__ == "__main__":
    import os

    port = int(os.environ.get("PORT", 5000))

    app.run(host="0.0.0.0", port=port)
import sqlite3
import hashlib

DB_NAME = "phishing_analyzer.db"


# -----------------------------
# INIT DB
# -----------------------------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            sender TEXT,
            subject TEXT,
            url_count INTEGER,
            is_hidden INTEGER DEFAULT 0,
            content_hash TEXT UNIQUE
        )
    """)

    conn.commit()
    conn.close()


# -----------------------------
# CREATE HASH (for duplicate detection)
# -----------------------------
def generate_hash(report):
    raw = f"{report.get('sender','')}|{report.get('subject','')}|{report.get('risk_score',0)}|{report.get('url_count',0)}"
    return hashlib.sha256(raw.encode()).hexdigest()


# -----------------------------
# SAVE ANALYSIS (NO DUPLICATES)
# -----------------------------
def save_analysis(report):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    content_hash = generate_hash(report)

    try:
        cursor.execute("""
            INSERT INTO analyses (
                timestamp,
                risk_score,
                risk_level,
                sender,
                subject,
                url_count,
                is_hidden,
                content_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            report.get("timestamp"),
            report.get("risk_score", 0),
            report.get("risk_level", ""),
            report.get("sender", ""),
            report.get("subject", ""),
            report.get("url_count", 0),
            0,
            content_hash
        ))

        conn.commit()

    except sqlite3.IntegrityError:
        # duplicate ignored
        print("Duplicate entry ignored")

    conn.close()


# -----------------------------
# HIDE HISTORY (SOFT DELETE)
# -----------------------------
def delete_all_history():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE analyses
        SET is_hidden = 1
    """)

    conn.commit()
    conn.close()


# -----------------------------
# RESTORE HISTORY
# -----------------------------
def restore_history():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE analyses
        SET is_hidden = 0
    """)

    conn.commit()
    conn.close()


# -----------------------------
# GET HISTORY
# -----------------------------
def get_history():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, timestamp, risk_score, risk_level, sender, subject, url_count
        FROM analyses
        WHERE is_hidden = 0
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()
    return rows


# -----------------------------
# RISK STATS (FOR CHART)
# -----------------------------
def get_risk_stats():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT risk_level, COUNT(*)
        FROM analyses
        WHERE is_hidden = 0
        GROUP BY risk_level
    """)

    rows = cursor.fetchall()
    conn.close()

    return rows


# -----------------------------
# DAILY STATS
# -----------------------------
def get_daily_stats():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT substr(timestamp,1,10) as day, COUNT(*)
        FROM analyses
        WHERE is_hidden = 0
        GROUP BY day
        ORDER BY day
    """)

    rows = cursor.fetchall()
    conn.close()
    return rows


# -----------------------------
# DELETE SINGLE ITEM
# -----------------------------
def delete_history_item(record_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE analyses
        SET is_hidden = 1
        WHERE id = ?
    """, (record_id,))

    conn.commit()
    conn.close()


# -----------------------------
# DEBUG
# -----------------------------
def get_total_records():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM analyses")
    count = cursor.fetchone()[0]

    conn.close()
    return count


# -----------------------------
# TEST
# -----------------------------
if __name__ == "__main__":
    init_db()
    print("Database initialized successfully!")
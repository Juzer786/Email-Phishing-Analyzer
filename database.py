import sqlite3

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
            is_hidden INTEGER DEFAULT 0
        )
    """)

    conn.commit()
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
# RESTORE HISTORY (OPTIONAL)
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
# SAVE ANALYSIS
# -----------------------------
def save_analysis(report):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO analyses (
            timestamp,
            risk_score,
            risk_level,
            sender,
            subject,
            url_count,
            is_hidden
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        report.get("timestamp"),
        report.get("risk_score", 0),
        report.get("risk_level", ""),
        report.get("sender", ""),
        report.get("subject", ""),
        report.get("url_count", 0),
        0
    ))

    conn.commit()
    conn.close()


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
# GET VISIBLE HISTORY ONLY
# -----------------------------
def get_history():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            risk_score,
            risk_level,
            sender,
            subject,
            url_count
        FROM analyses
        WHERE is_hidden = 0
        ORDER BY id DESC
    """)
    
    rows = cursor.fetchall()

    conn.close()
    return rows


# -----------------------------
# DEBUG: COUNT ALL RECORDS
# -----------------------------
def get_total_records():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM analyses")
    count = cursor.fetchone()[0]

    conn.close()
    return count

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
# TEST DB
# -----------------------------
if __name__ == "__main__":
    init_db()
    print("Database initialized successfully!")
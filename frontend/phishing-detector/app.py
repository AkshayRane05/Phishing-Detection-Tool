from flask import Flask, render_template
import psycopg2

app = Flask(__name__)

# PostgreSQL credentials
DB_HOST = "localhost"
DB_NAME = "phishing_detector"
DB_USER = "postgres"
DB_PASSWORD = "root"


def connect_db():
    """Connect to the PostgreSQL database."""
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )


@app.route("/")
def dashboard():
    """Render the dashboard."""
    # Fetch data from the database (example data for now)
    stats = {
        "total_scans": 8,
        "daily_scans": 4,
        "ai_reads": 175,
        "accuracy": 90,
    }

    detections = [
        {
            "status": "safe",
            "link": "https://www.google.com",
            "frequency": 7,
            "reported_time": "April 29, 2023, 9:37 a.m.",
            "domain": "www.google.com",
            "action": "Block",
        }
    ]

    trends_data = {
        "labels": ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
        "data": [12, 19, 3, 5, 2, 3],
    }

    detections_data = {
        "labels": ["Legitimate", "Suspicious", "Phishing"],
        "data": [70, 15, 15],
    }

    return render_template(
        "dashboard.html",
        stats=stats,
        detections=detections,
        trends_data=trends_data,
        detections_data=detections_data,
    )


@app.route("/api/stats")
def get_stats():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM stats ORDER BY id DESC LIMIT 1")
    stats = cursor.fetchone()
    cursor.close()
    conn.close()

    if stats:
        return {
            "total_scans": stats[1],
            "daily_scans": stats[2],
            "ai_reads": stats[3],
            "accuracy": stats[4],
        }
    return {"error": "No stats found."}, 404


@app.route("/api/phishing-emails")
def get_phishing_emails():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM phishing_emails ORDER BY timestamp DESC")
    emails = cursor.fetchall()
    cursor.close()
    conn.close()

    if emails:
        return [
            {
                "id": email[0],
                "sender": email[1],
                "subject": email[2],
                "body": email[3],
                "prediction": email[4],
                "confidence": email[5],
                "timestamp": email[6],
                "verified": email[7],
            }
            for email in emails
        ]
    return {"error": "No emails found."}, 404


@app.route("/api/phishing-emails", methods=["POST"])
def add_phishing_email():
    data = request.json
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO phishing_emails (sender, subject, body, prediction, confidence)
        VALUES (%s, %s, %s, %s, %s)
    """, (data["sender"], data["subject"], data["body"], data["prediction"], data["confidence"]))
    conn.commit()
    cursor.close()
    conn.close()
    return {"message": "Email added successfully."}, 201


@app.route("/api/phishing-emails/<int:email_id>/verify", methods=["PUT"])
def verify_phishing_email(email_id):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE phishing_emails SET verified = TRUE WHERE id = %s", (email_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return {"message": "Email verified successfully."}, 200


@app.route("/scan-text")
def scan_text():
    """Render the Scan Text page."""
    return render_template("scan_text.html")


@app.route("/alerts")
def alerts():
    """Render the Alerts page."""
    return render_template("alerts.html")


@app.route("/configuration")
def configuration():
    """Render the Configuration page."""
    return render_template("configuration.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

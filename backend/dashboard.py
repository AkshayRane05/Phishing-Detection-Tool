from flask import Flask, render_template, request, redirect, url_for
import psycopg2
import plotly.express as px
import pandas as pd

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
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM phishing_emails")
    emails = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("dashboard.html", emails=emails)


@app.route("/verify/<int:email_id>")
def verify_email(email_id):
    """Mark an email as verified."""
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE phishing_emails SET verified = TRUE WHERE id = %s", (email_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect(url_for("dashboard"))


@app.route("/trends")
def trends():
    """Generate trends/graphs."""
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT timestamp, COUNT(*) FROM phishing_emails GROUP BY timestamp")
    data = cursor.fetchall()
    cursor.close()
    conn.close()

    # Create a DataFrame for Plotly
    df = pd.DataFrame(data, columns=["timestamp", "count"])
    fig = px.line(df, x="timestamp", y="count",
                  title="Phishing Emails Over Time")
    graph_html = fig.to_html(full_html=False)

    return render_template("trends.html", graph_html=graph_html)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

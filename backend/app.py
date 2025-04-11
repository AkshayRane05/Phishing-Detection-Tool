from flask import Flask, jsonify, request
from threading import Thread
import sqlite3
import time
import os
import imaplib
import email
from email.header import decode_header
import re
import nltk
import pickle
import tensorflow as tf
import requests
from nltk.corpus import stopwords
from tensorflow.keras.preprocessing.text import Tokenizer  # type: ignore
from tensorflow.keras.preprocessing.sequence import pad_sequences  # type: ignore

nltk.download('stopwords')

app = Flask(__name__)

# Load model and tokenizer
model = tf.keras.models.load_model("phishing_email_detection_model.h5")
with open("tokenizer.pkl", "rb") as handle:
    tokenizer = pickle.load(handle)

# SQLite setup
DB_FILE = "emails.db"


def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT,
                subject TEXT,
                body TEXT,
                prediction TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()


init_db()

# Email settings
IMAP_SERVER = "imap.gmail.com"
EMAIL_ACCOUNT = "your-email-id"
EMAIL_PASSWORD = "your-email-password"

# Google Safe Browsing API
API_KEY = "your-api-key"
URL_CHECK_API_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

# Utility functions


def clean_text(text):
    text = re.sub(r'http\S+', '', text)
    text = re.sub(r'<.*?>', '', text)
    text = re.sub(r'[^a-zA-Z\s]', '', text)
    text = text.lower()
    stop_words = set(stopwords.words('english'))
    text = ' '.join([word for word in text.split() if word not in stop_words])
    return text


def predict_email(text):
    cleaned = clean_text(text)
    sequence = tokenizer.texts_to_sequences([cleaned])
    padded = pad_sequences(sequence, maxlen=100, padding="post")
    prediction = model.predict(padded)[0][0]
    if prediction > 0.5:
        return f"Phishing ({prediction*100:.2f}%)"
    return f"Legitimate ({(1-prediction)*100:.2f}%)"


def extract_urls(text):
    url_pattern = re.compile(r'http[s]?://\S+')
    return url_pattern.findall(text)


def check_url_phishing(url):
    payload = {
        "client": {"clientId": "email-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    res = requests.post(URL_CHECK_API_URL, json=payload)
    if res.status_code == 200:
        return "Phishing URL" if res.json().get('matches') else "Legit URL"
    return "Check Error"

# Email processing thread


def email_listener():
    while True:
        try:
            mail = imaplib.IMAP4_SSL(IMAP_SERVER)
            mail.login(EMAIL_ACCOUNT, EMAIL_PASSWORD)
            mail.select("inbox")
            result, data = mail.search(None, "UNSEEN")

            if result == "OK":
                for uid in data[0].split():
                    res, msg_data = mail.fetch(uid, "(RFC822)")
                    for response_part in msg_data:
                        if isinstance(response_part, tuple):
                            msg = email.message_from_bytes(response_part[1])
                            subject, encoding = decode_header(
                                msg["Subject"])[0]
                            if isinstance(subject, bytes):
                                subject = subject.decode(encoding or "utf-8")
                            sender = msg.get("From")
                            body = ""
                            if msg.is_multipart():
                                for part in msg.walk():
                                    if part.get_content_type() == "text/plain":
                                        body = part.get_payload(decode=True).decode(
                                            "utf-8", errors="ignore")
                                        break
                            else:
                                body = msg.get_payload(decode=True).decode(
                                    "utf-8", errors="ignore")

                            pred = predict_email(body)
                            with sqlite3.connect(DB_FILE) as conn:
                                conn.execute("INSERT INTO emails (sender, subject, body, prediction) VALUES (?, ?, ?, ?)",
                                             (sender, subject, body, pred))
                                conn.commit()
            mail.logout()
        except Exception as e:
            print("Error in email listener:", e)
        time.sleep(15)  # Check every 15 seconds


# Run email listener in background
Thread(target=email_listener, daemon=True).start()

# Flask routes


@app.route("/emails", methods=["GET"])
def get_emails():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM emails ORDER BY timestamp DESC LIMIT 20")
        rows = [dict(row) for row in c.fetchall()]
    return jsonify(rows)


@app.route("/predict", methods=["POST"])
def predict():
    data = request.json
    email_text = data.get("text", "")
    prediction = predict_email(email_text)
    return jsonify({"prediction": prediction})


@app.route("/check-url", methods=["POST"])
def check_url():
    data = request.json
    url = data.get("url", "")
    result = check_url_phishing(url)
    return jsonify({"result": result})


if __name__ == "__main__":
    app.run(debug=True)

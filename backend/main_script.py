import imaplib
import email
import time
import re
import nltk
import tensorflow as tf
import numpy as np
from nltk.corpus import stopwords
from email.header import decode_header
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
import pickle
import concurrent.futures
import os
import requests
import psycopg2
from twilio.rest import Client

# Ensure you have the necessary NLTK data
nltk.download('stopwords')

# IMAP credentials
IMAP_SERVER = "imap.gmail.com"
EMAIL_ACCOUNT = "g13lastyear@gmail.com"
EMAIL_PASSWORD = "ogkm bmqt xnqy ywrp"  # Use an App Password if 2FA is enabled

# File to store the last processed UID
UID_FILE = "last_processed_uid.txt"

# Load the trained model and tokenizer
model = tf.keras.models.load_model("phishing_email_detection_model.h5")
with open("tokenizer.pkl", "rb") as handle:
    tokenizer = pickle.load(handle)

# URL Phishing Detection API (Example: Google Safe Browsing)
API_KEY = "AIzaSyAP9Qzrx1loXi2iK47Zm-K0zsxreRrmlqM"
URL_CHECK_API_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

# Twilio credentials for SMS alerts
TWILIO_ACCOUNT_SID = "your_twilio_account_sid"
TWILIO_AUTH_TOKEN = "your_twilio_auth_token"
TWILIO_PHONE_NUMBER = "your_twilio_phone_number"
ADMIN_PHONE_NUMBER = "admin_phone_number"

# PostgreSQL credentials
DB_HOST = "localhost"
DB_NAME = "phishing_detector"
DB_USER = "your_db_user"
DB_PASSWORD = "your_db_password"


def connect_db():
    """Connect to the PostgreSQL database."""
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )


def save_phishing_email(sender, subject, body, prediction, confidence):
    """Save a phishing email to the database."""
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO phishing_emails (sender, subject, body, prediction, confidence)
        VALUES (%s, %s, %s, %s, %s)
    """, (sender, subject, body, prediction, confidence))
    conn.commit()
    cursor.close()
    conn.close()


def send_sms_alert(message):
    """Send an SMS alert using Twilio."""
    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    client.messages.create(
        body=message,
        from_=TWILIO_PHONE_NUMBER,
        to=ADMIN_PHONE_NUMBER
    )


def clean_text(text):
    """Clean and preprocess the text."""
    text = re.sub(r'http\S+', '', text)  # Remove URLs
    text = re.sub(r'<.*?>', '', text)  # Remove HTML tags
    text = re.sub(r'[^a-zA-Z\s]', '', text)  # Remove special characters
    text = text.lower()  # Convert to lowercase
    stop_words = set(stopwords.words('english'))
    # Remove stopwords
    text = ' '.join([word for word in text.split() if word not in stop_words])
    return text


def predict_email(email_text):
    """Predict if the email is phishing or legitimate."""
    cleaned_email = clean_text(email_text)  # Preprocess email
    sequence = tokenizer.texts_to_sequences(
        [cleaned_email])  # Convert text to numbers
    padded_sequence = pad_sequences(
        sequence, maxlen=100, padding="post", truncating="post")  # Pad sequence
    prediction = model.predict(padded_sequence)[0][0]  # Get prediction score

    if prediction > 0.5:
        return "Phishing (Confidence: {:.2f}%)".format(prediction * 100), prediction
    else:
        return "Legitimate (Confidence: {:.2f}%)".format((1 - prediction) * 100), prediction


def check_url_phishing(url):
    """Check if a URL is phishing using Google Safe Browsing API."""
    payload = {
        "client": {
            "clientId": "phishing-detector-app",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(URL_CHECK_API_URL, json=payload)
    if response.status_code == 200:
        result = response.json()
        if result.get('matches'):
            return "Phishing URL detected"
        else:
            return "Legitimate URL"
    else:
        return "Error checking URL"


def extract_urls(text):
    """Extract URLs from the text."""
    url_pattern = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    return url_pattern.findall(text)


def get_last_email_uid(mail):
    """Fetch the latest email UID."""
    mail.select("inbox")
    status, messages = mail.search(None, "ALL")  # Get all emails

    if status == "OK" and messages[0]:
        return messages[0].split()[-1]  # Return the last email UID
    return None


def load_last_processed_uid():
    """Load the last processed UID from the file."""
    if os.path.exists(UID_FILE):
        with open(UID_FILE, "r") as f:
            return f.read().strip()
    return None


def save_last_processed_uid(uid):
    """Save the last processed UID to the file."""
    with open(UID_FILE, "w") as f:
        f.write(uid.decode() if isinstance(uid, bytes) else str(uid))


def move_to_spam(mail, uid):
    """Move an email to the spam folder."""
    try:
        # Copy the email to the spam folder
        mail.uid("COPY", uid, "[Gmail]/Spam")
        # Delete the email from the inbox
        mail.uid("STORE", uid, "+FLAGS", "\\Deleted")
        mail.expunge()
        print(f"📨 Moved email {uid} to spam.")
    except Exception as e:
        print(f"⚠ Error moving email to spam: {e}")


def process_email(uid, mail):
    """Process a single email."""
    res, msg_data = mail.uid("FETCH", uid, "(RFC822)")
    for response_part in msg_data:
        if isinstance(response_part, tuple):
            msg = email.message_from_bytes(response_part[1])

            # Decode subject and sender
            subject, encoding = decode_header(msg["Subject"])[0]
            if isinstance(subject, bytes):
                subject = subject.decode(encoding or "utf-8")

            sender = msg.get("From")
            print(f"\n📩 New Email from {sender} - {subject}")

            # Extract email body
            body = None
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition"))

                    if content_type == "text/plain" and "attachment" not in content_disposition:
                        body = part.get_payload(decode=True).decode(
                            "utf-8", errors="ignore")
                        # Extract URLs before cleaning the text
                        urls = extract_urls(body)
                        body = clean_text(body)
                        break
            else:
                body = msg.get_payload(decode=True).decode(
                    "utf-8", errors="ignore")
                # Extract URLs before cleaning the text
                urls = extract_urls(body)
                body = clean_text(body)

            print("\n📜 Email Body:\n", body if body else "⚠ No body found.")

            # Predict if the email is phishing or legitimate
            if body:
                prediction, confidence = predict_email(body)
                print(f"🔍 Email Prediction: {prediction}")

                # Check URLs if any were found
                if urls:
                    print("\n🔗 URLs found in the email:")
                    for url in urls:
                        url_status = check_url_phishing(url)
                        print(f"   {url} - {url_status}")
                else:
                    print("\n🔍 No URLs found in the email")

                # Save phishing emails to the database
                if "Phishing" in prediction:
                    save_phishing_email(
                        sender, subject, body, prediction, confidence)
                    # Send SMS alert
                    send_sms_alert(
                        f"Phishing email detected from {sender}: {subject}")
                    # Move phishing email to spam
                    move_to_spam(mail, uid)

            # Mark email as read
            mail.uid("STORE", uid, "+FLAGS", "\\Seen")


def process_new_emails(mail, last_uid):
    """Fetch and process only new emails received after last_uid."""
    mail.select("inbox")

    # Ensure last_uid is properly formatted
    if last_uid is None:
        last_uid = get_last_email_uid(mail)
        if last_uid is None:
            print("⚠ No emails found in the inbox.")
            return None

    # Fetch emails with UID greater than last_uid
    status, messages = mail.uid(
        "SEARCH", None, f"UID {last_uid.decode() if isinstance(last_uid, bytes) else last_uid}:*")

    if status == "OK" and messages[0]:
        # Ignore first UID (already processed)
        email_uids = messages[0].split()[1:]

        # Process emails in parallel
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(process_email, uid, mail)
                       for uid in email_uids]
            concurrent.futures.wait(futures)

        # Update last processed UID
        if email_uids:
            save_last_processed_uid(email_uids[-1])
            return email_uids[-1]
    return last_uid


def email_listener():
    """Continuously fetch new emails every 10 seconds."""
    while True:
        try:
            mail = imaplib.IMAP4_SSL(IMAP_SERVER)
            mail.login(EMAIL_ACCOUNT, EMAIL_PASSWORD)
            print("📡 Listening for new emails... (Press Ctrl+C to stop)")

            # Load the last processed UID or fetch the latest UID
            last_uid = load_last_processed_uid()
            if not last_uid:
                last_uid = get_last_email_uid(mail)
                save_last_processed_uid(last_uid)
            print(f"📥 Starting from UID: {last_uid}")

            while True:
                last_uid = process_new_emails(
                    mail, last_uid)  # Process only new emails
                time.sleep(10)  # Wait 10 seconds before checking again

        except imaplib.IMAP4.abort:
            print("\n⚠ Connection lost. Reconnecting in 5 seconds...")
            time.sleep(5)

        except KeyboardInterrupt:
            print("\n🔌 Stopping email listener.")
            break

        finally:
            try:
                mail.close()
                mail.logout()
            except:
                pass


# Start email listener
email_listener()

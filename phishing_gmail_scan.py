import os
import base64
import re
import joblib
import pandas as pd
import nltk
import time
from email import message_from_bytes
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

nltk.download('stopwords')
stop_words = set(stopwords.words('english'))
stemmer = PorterStemmer()

SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

def clean_text(text):
    text = str(text).lower()
    text = re.sub(r"http\S+|www\S+|https\S+", '', text)
    text = re.sub(r"\W", ' ', text)
    text = re.sub(r"\s+", ' ', text)
    tokens = text.split()
    tokens = [stemmer.stem(word) for word in tokens if word not in stop_words]
    return " ".join(tokens)

def extract_phishing_reasons(text):
    reasons = []
    if re.search(r'https?://(bit\.ly|tinyurl|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', text):
        reasons.append("Reason: Suspicious Link")
    if re.search(r'verify your|click here|update account|login now', text, re.IGNORECASE):
        reasons.append("Reason: Urgent Language")
    if "<script" in text.lower() or "<html" in text.lower():
        reasons.append("Reason: HTML/Script Content")
    if re.search(r'password|ssn|bank account|credit card|confirm identity', text, re.IGNORECASE):
        reasons.append("Reason: Sensitive Request")
    return reasons if reasons else ["Reason: Not obvious"]

def authenticate_gmail():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
        creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return build('gmail', 'v1', credentials=creds)

def get_or_create_label(service, label_name):
    labels = service.users().labels().list(userId='me').execute().get('labels', [])
    for label in labels:
        if label['name'].lower() == label_name.lower():
            return label['id']
    label_obj = {
        'name': label_name,
        'labelListVisibility': 'labelShow',
        'messageListVisibility': 'show'
    }
    new_label = service.users().labels().create(userId='me', body=label_obj).execute()
    return new_label['id']

def fetch_and_classify(service, max_emails=10):
    model = joblib.load('phishing_model.joblib')
    vectorizer = joblib.load('vectorizer.joblib')
    phishing_label_id = get_or_create_label(service, 'Phishing')

    results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=max_emails).execute()
    messages = results.get('messages', [])
    output = []

    for msg in messages:
        msg_id = msg['id']
        msg_data = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()
        raw_msg = base64.urlsafe_b64decode(msg_data['raw'].encode('ASCII'))
        mime_msg = message_from_bytes(raw_msg)

        subject = mime_msg['subject']
        body = ""

        if mime_msg.is_multipart():
            for part in mime_msg.walk():
                if part.get_content_type() == "text/plain" and 'attachment' not in str(part.get('Content-Disposition', '')):
                    try:
                        body = part.get_payload(decode=True).decode(errors='ignore')
                        break
                    except:
                        continue
        else:
            try:
                body = mime_msg.get_payload(decode=True).decode(errors='ignore')
            except:
                continue

        cleaned = clean_text(body)
        vector = vectorizer.transform([cleaned])
        prediction = model.predict(vector)[0]
        label = 'Phishing' if prediction == 1 else 'Legit'
        reasons = extract_phishing_reasons(body)

        if prediction == 1:
            label_ids = [phishing_label_id]
            for reason in reasons:
                label_ids.append(get_or_create_label(service, reason))
            service.users().messages().modify(
                userId='me',
                id=msg_id,
                body={'addLabelIds': label_ids}
            ).execute()

        output.append({'Subject': subject, 'Prediction': label, 'Reasons': ", ".join(reasons)})

    return pd.DataFrame(output)

# ==========================
# Loop Runner
# ==========================
if __name__ == '__main__':
    service = authenticate_gmail()
    while True:
        print("Checking for phishing emails...")
        try:
            results_df = fetch_and_classify(service, max_emails=10)
            print("Results:")
            print(results_df)
        except Exception as e:
            print(f"Error during scanning: {e}")
        print("Sleeping for 45 minutes...\n")
        time.sleep(45 * 60)  # Sleep for 45 minutes

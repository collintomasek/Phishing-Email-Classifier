import re
import joblib
import pandas as pd
import streamlit as st
import imaplib
import email
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
import nltk

nltk.download('stopwords')

# ==========================
# Load Pretrained Model & Vectorizer
# ==========================
clf = joblib.load("phishing_model.joblib")
vectorizer = joblib.load("vectorizer.joblib")

# ==========================
# Clean Text Function
# ==========================
stop_words = set(stopwords.words('english'))
stemmer = PorterStemmer()

def clean_text(text):
    text = str(text).lower()
    text = re.sub(r"http\S+|www\S+|https\S+", '', text)
    text = re.sub(r"\W", ' ', text)
    text = re.sub(r"\s+", ' ', text)
    tokens = text.split()
    tokens = [stemmer.stem(word) for word in tokens if word not in stop_words]
    return " ".join(tokens)

# ==========================
# Streamlit UI
# ==========================
st.title("Phishing Email Classifier (Fast Version)")

email_input = st.text_area("Paste the email content below:")
if st.button("Classify"):
    email_cleaned = clean_text(email_input)
    vectorized = vectorizer.transform([email_cleaned])
    result = clf.predict(vectorized)[0]
    st.markdown("### Result:")
    st.success("Legitimate Email") if result == 0 else st.error("Phishing Email!")

# ==========================
# Email Login and Scan
# ==========================
st.subheader("Scan Your Email Inbox (IMAP)")

with st.form("email_form"):
    email_user = st.text_input("Email address")
    email_pass = st.text_input("App password (not your real password)", type="password")
    num_to_fetch = st.number_input("Number of recent emails to scan", min_value=1, max_value=50, value=10)
    submitted = st.form_submit_button("Scan Inbox")

if submitted:
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(email_user, email_pass)
        mail.select("inbox")

        st.success("Logged in successfully!")
        result, data = mail.search(None, "ALL")
        email_ids = data[0].split()[-num_to_fetch:]
        results = []

        for eid in reversed(email_ids):
            res, msg_data = mail.fetch(eid, "(RFC822)")
            raw = msg_data[0][1]
            msg = email.message_from_bytes(raw)
            subject = msg["subject"]
            body = ""

            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode(errors="ignore")
                        break
            else:
                body = msg.get_payload(decode=True).decode(errors="ignore")

            cleaned = clean_text(body)
            prediction = clf.predict(vectorizer.transform([cleaned]))[0]
            results.append({
                "Subject": subject,
                "Prediction": "Phishing" if prediction == 1 else "Legit"
            })

        result_df = pd.DataFrame(results)
        st.dataframe(result_df)

    except Exception as e:
        st.error(f"Error: {e}")

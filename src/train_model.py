import re
import pandas as pd
import joblib
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import nltk

nltk.download('stopwords')


# Clean Text Function
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

# Load and Clean Dataset
df = pd.read_csv("combined_emails.csv")
df['body_cleaned'] = df['body'].apply(clean_text)

# Vectorize and Train Model
vectorizer = TfidfVectorizer(max_features=3000)
X = vectorizer.fit_transform(df['body_cleaned'])
y = df['label']

clf = RandomForestClassifier(n_estimators=100)
clf.fit(X, y)

# Save Model and Vectorizer
joblib.dump(clf, 'phishing_model.joblib')
joblib.dump(vectorizer, 'vectorizer.joblib')
print("Model and vectorizer saved successfully.")


#zpmhsmjzluvavvtk


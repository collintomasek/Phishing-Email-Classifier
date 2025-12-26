# Phishing Email Classifier

A machine-learning–based phishing detection system that classifies emails as
**phishing** or **legitimate** using natural language processing and supervised learning.

This project combines multiple public datasets and demonstrates a realistic
blue-team workflow: data ingestion, feature engineering, model training,
evaluation, and optional Gmail-based scanning.

---

## Overview

Phishing remains one of the most common initial access vectors in cyber attacks.
This project addresses that problem by building a classifier that analyzes email
content and predicts whether an email is malicious.

The system is designed to be:
- reproducible
- extensible
- safe to share publicly (no sensitive data or secrets included)

---

## Dataset

This project uses a combination of publicly available phishing and spam datasets,
including sources such as:
- Enron
- SpamAssassin
- CEAS
- Nazario
- Nigerian fraud datasets

Due to dataset size, licensing, and potential sensitivity, **raw CSV files are
not included in this repository**.

See `data/README.md` for details on dataset handling.

---

## Approach

- **Text preprocessing**
  - Cleaning and normalization
  - Tokenization
- **Feature extraction**
  - TF-IDF vectorization
- **Modeling**
  - Classical supervised machine learning
  - Binary classification (phishing vs legitimate)
- **Evaluation**
  - Precision, recall, F1-score (weighted and macro averages)
  - Confusion matrix
- **Persistence**
  - Trained model and vectorizer saved locally via `joblib`

---

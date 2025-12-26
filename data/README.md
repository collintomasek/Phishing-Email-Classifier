# Data

This project uses multiple public phishing and spam datasets
(e.g. Enron, SpamAssassin, CEAS, Nazario).

Raw datasets are not included in this repository due to:
- size constraints
- licensing considerations
- potential sensitive content

## How data is used
- Datasets are combined and labeled locally
- Text is vectorized using TF-IDF
- Train/test splits are created during training

Refer to `src/train_model.py` for preprocessing logic.

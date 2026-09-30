# Rule-Based Intrusion Detection System

A Network Intrusion Detection System that analyzes network traffic features and detects potential intrusions using a trained machine learning model.
![Traffic Analysis Form 1](Traffic%20Anaylsis%281%29.png)
![Traffic Analysis Form 2](Traffic%20Anaylsis%20%282%29.png)

## Tech Stack
Python, Flask, Flask-SocketIO, PyShark, scikit-learn, pandas, joblib

## Features
- Web form to enter network connection features (protocol, service, flags, etc.) and get an intrusion prediction
- Live network monitoring page using PyShark packet capture
- Trained ML model with saved encoder and scaler (joblib .pkl files)

## How to Run
1. `pip install -r requirements.txt`
2. `python app.py`
3. Open http://127.0.0.1:5000 in your browser

## Dataset
Network traffic dataset (lda.csv) with connection-level features used for training.

## Note
The trained model file (model.pkl, 33 MB) is not included in this repository due to GitHub's file size limits. All source code, preprocessing files (encoder.pkl, scaler.pkl), dataset, and notebooks are included.

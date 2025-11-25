# EV CAN Bus Intrusion Detection System (IDS)
A Lightweight Machine Learning–Based IDS for Electric Vehicle CAN Networks

---

## Overview

This project implements an anomaly-based Intrusion Detection System (IDS) for Electric Vehicle (EV) Controller Area Network (CAN) communication using machine learning.  
The CAN bus lacks authentication, message integrity and encryption, making it vulnerable to cyberattacks.  
This IDS uses an unsupervised Isolation Forest model to detect abnormal CAN behaviour based on timing and payload patterns.

The system processes more than 4.7 million CAN messages from the HCRL CAN Intrusion Dataset, with engineered behavioural features to detect:
- DoS attacks  
- Fuzzy attacks  
- Impersonation attacks  

The pipeline was fully implemented in Python using Google Colab.

---

## Key Features

- Unsupervised anomaly detection using Isolation Forest  
- Behaviour-based feature engineering, including:  
  - Timing intervals  
  - Rolling statistics  
  - Burstiness and jitter  
  - Payload entropy  
  - Bit-flip count  
  - Payload correlation  
  - Sequence prediction error  
- Complete end-to-end workflow:
  - Dataset parsing  
  - Feature extraction  
  - Model training  
  - Anomaly score computation  
  - Prediction using a fixed threshold of 0.1  
  - Full evaluation and visualisation  

---

## Performance Summary

Threshold Used: 0.1

| Metric | Score |
|--------|--------|
| Accuracy | 84.80% |
| Recall (Attack Detection Rate) | 89.32% |
| Precision | 93.63% |
| False Positive Rate | 59.51% |
| TP / FP / TN / FN | 1,983,963 / 134,997 / 91,854 / 237,203 |

---

## Testing and Validation

Validation steps include:
- Dataset conversion verification  
- Feature engineering execution logs  
- Isolation Forest training confirmation  
- Anomaly score and prediction generation  
- Evaluation using accuracy, recall, precision and FPR  
- Confusion matrix  
- Classification report  
- Anomaly score distribution  
- Full visual analytics  

---

## Technologies Used

- Python 3
- pandas  
- NumPy  
- SciPy  
- scikit-learn  
- Matplotlib  
- Google Colab  
- HCRL CAN Intrusion Dataset  

---


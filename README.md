EV CAN Bus Intrusion Detection System (IDS)

A Lightweight Machine Learning–Based IDS for Electric Vehicle CAN Networks

Overview

This project implements an anomaly-based Intrusion Detection System (IDS) for Electric Vehicle (EV) CAN bus networks using machine learning.
The CAN bus is critical for EV communication but lacks authentication, integrity checks, and encryption. This makes it vulnerable to cyberattacks such as:

DoS (Denial of Service)

Fuzzy Attacks

Impersonation Attacks

To address this, a lightweight IDS was developed using the Isolation Forest algorithm, trained exclusively on normal CAN traffic from the HCRL CAN Intrusion Dataset.
Over 4.7 million messages were processed, with extensive feature engineering and full evaluation.

Key Features
Unsupervised ML Model (Isolation Forest)

No labelled attack data required

Efficient for real-time or embedded ECU deployment

Advanced Feature Engineering

Extracts behaviour-based indicators including:

Message timing & delta intervals

Rolling statistics

Burstiness & jitter

Payload entropy

Bit-flip count

Payload correlation

Sequence prediction error

End-to-End Implementation

Includes:

Raw CAN dataset parsing

Cleaning & preprocessing

Feature engineering

Model training

Anomaly scoring

Threshold testing

Full performance evaluation

Visualisation outputs

Tested on Real EV Dataset (HCRL)

Attack datasets include DoS, Fuzzy, and Impersonation scenarios.

Performance Summary

Optimal Threshold Selected: 0.1

Metric	Score
Accuracy	84.80%
Recall (Attack Detection)	89.32%
Precision	93.63%
False Positive Rate (FPR)	59.51%
TP / FP / TN / FN	1,983,963 / 134,997 / 91,854 / 237,203

Support

If you found this project useful, please star ⭐ the repository and share it with others working on EV cybersecurity.

# EV CAN Bus Intrusion Detection System

This is my final-year project for my BSc Cybersecurity degree at Kingston University. In this project, I have developed a lightweight anomaly-based Intrusion Detection System (IDS) that detects cyberattacks on Electric Vehicle (EV) CAN bus networks using machine learning.

---

## Overview

Electric Vehicles (EVs) rely on the Controller Area Network (CAN) to allow different electronic components (ECUs) to communicate with each other. However, the CAN protocol lacks built-in security, making it vulnerable to attacks like message spoofing, denial-of-service (DoS), and fuzzing.

This project aims to design and build an IDS using Python that can analyze CAN traffic and detect anomalies in real-time using the Isolation Forest algorithm.

---

## Dataset

I used the **HCRL CAN Intrusion Dataset**, a publicly available dataset containing both normal and malicious CAN traffic. It includes four types of files:

- `Attack_free_dataset.txt` (normal data)
- `DoS_attack_dataset.txt`
- `Fuzzy_attack_dataset.txt`
- `Impersonation_attack_dataset.txt`

> Note: Due to GitHub’s file size limitations, I haven’t uploaded these dataset files here.  
You can download them from the official source:  
👉 https://ocslab.hksecurity.net/Dataset/CAN-intrusion-dataset

---

## Tools and Technologies

- Python (3.x)
- Google Colab (main notebook)
- pandas, scikit-learn, matplotlib, seaborn
- Isolation Forest (unsupervised anomaly detection algorithm)

---

## Project Structure

EV-CAN-IDS/
├── data/ # Dataset files (not uploaded due to size)
├── notebooks/
│ └── ev_can_ids.ipynb # Main development notebook
├── imgs/ # Graphs and screenshots (to be added)
├── README.md # This file

---

## Methodology

I followed the CRISP-DM approach:

1. **Understanding the problem** – Why CAN bus needs protection in EVs
2. **Data understanding** – Loaded and explored the HCRL dataset
3. **Data preparation** – Cleaned data and engineered useful features
4. **Modeling** – Trained an Isolation Forest on normal data only
5. **Evaluation** – Tested the model on attack data and analyzed results
6. **Documentation** – Collected graphs and findings for final report

---

## Current Status

- [x] Dataset loaded and explored
- [x] Isolation Forest model implemented
- [ ] Evaluation graphs and metrics to be finalized
- [ ] Final documentation and GitHub polishing

---

## Results (To be added soon)

Once I complete the testing and visualizations, I will upload screenshots and evaluation metrics here.

---

## License

This project is open-source and released under the **MIT License**.

---

## Author

**Suhail Kider**  
Student ID: K2525456  
Final-year Cybersecurity student at Kingston University

# Multi-Layered Intrusion Prevention System (IPS) using Machine Learning

This repository contains the source code, pre-trained models, and documentation for an AI-driven Intrusion Prevention System. The project aims to dynamically detect and mitigate cyber threats across multiple OSI layers, overcoming the limitations of traditional static, rule-based firewalls.

Developed as part of the CS 484 - Introduction to Machine Learning course at the Illinois Institute of Technology (Spring 2026).

## Project Architecture

The system is divided into two active defense mechanisms:

### Phase 1: Network-Layer Analysis (OSI Layers 3 & 4)
Focuses on detecting and blocking network brute-force and reconnaissance activities.
* Threats mitigated: Denial of Service (DoS) and Probing (e.g., Nmap scans, hping3 floods).
* Dataset: NSL-KDD.
* Model: Support Vector Machine (SVM) optimized for Recall (minimizing False Negatives).
* Mechanism: Real-time packet sniffing using pyshark. Extracts connection duration, byte size, and TCP flags. Malicious sources are instantly blocked at the system level using iptables.

### Phase 2: Application-Layer Web Application Firewall (OSI Layer 7)
Focuses on Deep Packet Inspection (DPI) to protect web applications against payload-based attacks.
* Threat mitigated: SQL Injection (SQLi), including obfuscated and encoded payloads.
* Dataset: Modified SQL Dataset (Kaggle).
* Model: Random Forest Classifier (200 trees) combined with a Hybrid NLP pipeline.
* Mechanism: Intercepts HTTP traffic targeting web services on port 3000 (e.g., OWASP Juice Shop). Decodes payloads and applies TF-IDF vectorization (5000 N-grams) alongside deterministic feature extraction. Blocks malicious requests dynamically.

## Technology Stack
* Language: Python 3
* Machine Learning: Scikit-Learn, Pandas, NumPy, SciPy, Joblib
* Network Analysis: PyShark (Tshark wrapper)
* System/Mitigation: Linux iptables

## Repository Structure
* model.py : Script to download the NSL-KDD dataset, preprocess data (StandardScaler, One-Hot Encoding), train multiple models (Logistic Regression, SVM, LDA, Naive Bayes), and evaluate them for Phase 1.
* live_ips.py : The real-time packet sniffing and mitigation script for Phase 1. It loads the pre-trained SVM model and intercepts network layer attacks.
* ml_model.py : Script to download the Kaggle SQLi dataset, perform NLP feature engineering (TF-IDF and manual feature extraction), and train the Random Forest model for Phase 2.
* sqli_detector.py : The real-time Deep Packet Inspection (DPI) script for Phase 2. It monitors port 3000, decodes HTTP payloads, and blocks SQL injections using the trained Random Forest model.

## Disclaimer
This project is an academic prototype developed for educational purposes. It requires root/sudo privileges to manipulate iptables rules. Do not deploy in a production environment without proper architectural reviews.

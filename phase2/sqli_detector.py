import pyshark
import urllib.parse
import os
import joblib
import numpy as np
from scipy.sparse import hstack

# 1. Chargement des modèles (Phase 2 - Kaggle)
try:
    print("LOG: Loading SQLi ML models...")
    model = joblib.load("sqli_model.pkl")
    vectorizer = joblib.load("vectorizer.pkl")
    print("LOG: Models loaded and ready.")
except Exception as e:
    print(f"ERROR: Models not found. Run ml_model.py first! ({e})")
    exit()

def extract_manual_features(text):
    """Caractéristiques manuelles pour renforcer la détection ML"""
    text = text.lower()
    return np.array([
        text.count("'"), text.count('"'), text.count("--"),
        text.count("/*"), text.count("*/"), text.count(" or "),
        text.count(" and "), text.count("union"), text.count("select"),
        text.count("sleep"), len(text), int(" or " in text),
        int("union" in text), int("select" in text), 
        int("information_schema" in text),
    ])

def decode_payload(raw_data):
    """Transforme l'hexadécimal de Juice Shop (7b:22...) en texte clair"""
    try:
        # Si c'est de l'hexadécimal avec des deux-points
        if ":" in raw_data:
            clean_hex = raw_data.replace(":", "").strip()
            return bytes.fromhex(clean_hex).decode('utf-8', errors='ignore')
        # Si c'est déjà du texte ou du JSON standard
        return raw_data
    except:
        return raw_data

def predict_sqli(payload):
    """Analyse le texte via TF-IDF + Features manuelles"""
    payload_clean = urllib.parse.unquote(payload).lower()
    
    # Transformation via Vectorizer
    vec = vectorizer.transform([payload_clean])
    # Extraction des patterns
    feat = extract_manual_features(payload_clean).reshape(1, -1)
    
    # Fusion et Prédiction
    final = hstack([vec, feat])
    proba = model.predict_proba(final)[0][1]
    return proba

def process_packet(packet):
    try:
        payload = ""
        src_ip = packet.ip.src
        
        # --- CAPTURE ET DÉCODAGE ---
        if hasattr(packet, 'http'):
            # Analyse de l'URL
            if hasattr(packet.http, 'request_uri'):
                payload += urllib.parse.unquote(packet.http.request_uri)
            
            # Analyse du Body (POST/JSON)
            if hasattr(packet.http, 'file_data'):
                raw_body = str(packet.http.file_data)
                payload += " " + decode_payload(raw_body)
        
        # Backup : Si Pyshark ne voit pas de couche HTTP (trafic brut)
        elif hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
            raw_hex = packet.tcp.payload.replace(':', '')
            payload = bytes.fromhex(raw_hex).decode('utf-8', errors='ignore')

        if payload:
            payload_clean = payload.lower().strip()
            
            # 1. Détection Hybride (Mots-clés + IA)
            # Ajout de variations pour Juice Shop
            keywords = ["' or", "--", "union select", "drop table", "1=1", "admin' --"]
            keyword_match = any(k in payload_clean for k in keywords)
            
            score = predict_sqli(payload_clean)

            # 2. Verdict
            if score > 0.75 or keyword_match:
                print(f"\n[!!!] SQL INJECTION DETECTED [!!!]")
                print(f"SOURCE IP : {src_ip}")
                print(f"DETECTION : {'Rule-based' if keyword_match else 'AI-based'}")
                print(f"CONFIDENCE: {round(score, 3)}")
                print(f"PAYLOAD   : {payload_clean}")
                
                # ACTION : Coupure immédiate du flux
                print(f"ACTION    : Banning IP {src_ip} via iptables...")
                os.system(f"sudo iptables -I INPUT 1 -s {src_ip} -j DROP")
                print("-" * 40)
            else:
                # Log de monitoring normal
                print(f"MONITORING: {src_ip} -> {payload_clean[:70]}...")

    except Exception as e:
        pass

def main():
    print("WAF MODE: Protecting Juice Shop on Port 3000 (Interface: lo)")
    print("Press Ctrl+C to stop and 'sudo iptables -F' to unban.")
    
    # Utilisation du port 3000 spécifique pour Juice Shop
    capture = pyshark.LiveCapture(
        interface='lo', 
        bpf_filter='tcp port 3000'
    )
    
    for packet in capture.sniff_continuously():
        process_packet(packet)

if __name__ == "__main__":
    main()
import joblib
import pandas as pd
import pyshark
import sys
import os

#Load Models
try:
    svm = joblib.load('best_svm.pkl')
    scaler = joblib.load('scaler.pkl')
    expected_columns = scaler.feature_names_in_
except Exception as e:
    print(f"ERROR: Model loading failed: {e}")
    sys.exit()

def ban_ip(ip):
    os.system(f"sudo iptables -I INPUT 1 -i lo -s {ip} -j DROP")

# Interface 'lo' is used for local loopback testing (127.0.0.1)
interface = 'lo' 
print(f"LOG: Monitoring and Protection active on interface: '{interface}'")

capture = pyshark.LiveCapture(interface=interface)
paquets_buffer = []

# Tracker for banned addresses to avoid redundant system calls
banned_ips = set()

try:
    for paquet in capture.sniff_continuously():
        if 'IP' in paquet:
            paquets_buffer.append(paquet)
        
        # Buffer threshold set to 1 for immediate real-time response
        if len(paquets_buffer) >= 1:
            data_df = pd.DataFrame(0, index=[0], columns=expected_columns)
            
            try:
                # --- FEATURE EXTRACTION ---
                duration = float(paquets_buffer[-1].sniff_timestamp) - float(paquets_buffer[0].sniff_timestamp)
                data_df['duration'] = duration
                data_df['src_bytes'] = sum(int(p.ip.len) for p in paquets_buffer)
                data_df['count'] = len(paquets_buffer)
                
                proto = paquets_buffer[0].transport_layer if paquets_buffer[0].transport_layer else "TCP"
                col_proto = f"protocol_type_{proto.lower()}"
                if col_proto in expected_columns:
                    data_df[col_proto] = 1

                if proto == "TCP":
                    # Mapping local scan patterns to NSL-KDD features
                    if 'flag_S0' in expected_columns: 
                        data_df['flag_S0'] = 1
                    if 'service_private' in expected_columns: 
                        data_df['service_private'] = 1

                # --- INFERENCE & MITIGATION ---
                data_scaled = scaler.transform(data_df)
                prediction = svm.predict(data_scaled)
                
                src_ip = paquets_buffer[0].ip.src

                if prediction[0] == 1:
                    print(f"ALERT: Intrusion signature detected from {src_ip}")
                    if src_ip not in banned_ips:
                        ban_ip(src_ip)
                        banned_ips.add(src_ip)
                        print(f"FIREWALL: Source {src_ip} successfully blocked.")
                else:
                    print(f"STATUS: Normal traffic from {src_ip}")

            except Exception as e:
                # Ignore malformed packets or processing errors
                pass
            
            # Clear buffer for next sequence
            paquets_buffer = []

except KeyboardInterrupt:
    print("\nLOG: Shutting down IPS...")
    # Optional: Clear firewall rules on exit
    # os.system("sudo iptables -F")
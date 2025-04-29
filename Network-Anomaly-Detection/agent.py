import time
import json
import requests

ALERT_FILE = "network_alerts.json"
EDR_SERVER_URL = "http://localhost:5000/api/alerts"  # EDR dashboard endpoint

def tail_alerts():
    print("[*] EDR Agent started. Monitoring alerts...")
    with open(ALERT_FILE, "r") as f:
        f.seek(0, 2)  # Seek to end of file

        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue

            try:
                alert = json.loads(line.strip())
                forward_alert(alert)
            except Exception as e:
                print("[!] Failed to process alert:", e)

def forward_alert(alert):
    try:
        response = requests.post(EDR_SERVER_URL, json=alert)
        if response.status_code == 200:
            print(f"[+] Alert forwarded: {alert['technique_id']} - {alert['description']}")
        else:
            print(f"[!] Failed to forward alert: {response.status_code}")
    except Exception as e:
        print(f"[!] Network error: {e}")

if __name__ == "__main__":
    tail_alerts()

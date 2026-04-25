from flask import Flask, jsonify
import pyshark
from ja3 import compute_ja3_from_packet
from threat_db import check_threat
from flask_cors import CORS
app = Flask(__name__)
CORS(app) 
alerts = []

INTERFACE = "ens33"  # your interface


def capture_packets():
    print("[*] Real JA3 Capture Started...")

    capture = pyshark.LiveCapture(
        interface=INTERFACE,
        display_filter="tls.handshake.type == 1"
    )

    for packet in capture.sniff_continuously():
        try:
            src = packet.ip.src
            dst = packet.ip.dst

            ja3_string, ja3_hash = compute_ja3_from_packet(packet)

            if not ja3_hash:
                continue

            threat = check_threat(ja3_hash)

            data = {
                "src": src,
                "dst": dst,
                "ja3": ja3_hash,
                "threat": threat if threat else "Benign"
            }

            print("[JA3]", data)

            alerts.append(data)

            if len(alerts) > 50:
                alerts.pop(0)

        except Exception:
            continue


@app.get("/")
def root():
    return {"message": "Backend is Running"}
    
    
@app.route("/alerts")
def get_alerts():
    return jsonify(alerts)


if __name__ == "__main__":
    import threading

    t = threading.Thread(target=capture_packets)
    t.daemon = True
    t.start()

    app.run(host="0.0.0.0", port=5000)

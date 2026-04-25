from flask import Flask, jsonify
from flask_cors import CORS
import pyshark
import threading
import logging

from ja3 import compute_ja3_from_packet
from threat_db import check_threat

# ---------- Flask Setup ----------
app = Flask(__name__)
CORS(app)

# Disable noisy request logs (optional)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# ---------- Global Storage ----------
alerts = []

# Change if needed (check using: ip a)
INTERFACE = "ens33"


# ---------- Packet Capture ----------
def capture_packets():
    print("[*] Real JA3 Capture Started on", INTERFACE)

    capture = pyshark.LiveCapture(
        interface=INTERFACE,
        display_filter="tls.handshake.type == 1"  # ClientHello only
    )

    for packet in capture.sniff_continuously():
        try:
            # Ensure packet has IP + TLS
            if not hasattr(packet, "ip") or not hasattr(packet, "tls"):
                continue

            src = packet.ip.src
            dst = packet.ip.dst

            # Compute JA3
            ja3_string, ja3_hash = compute_ja3_from_packet(packet)

            if not ja3_hash:
                # Debug: see why it's skipping
                print("[DEBUG] JA3 not extracted")
                continue

            # Threat lookup
            threat = check_threat(ja3_hash)

            data = {
                "src": src,
                "dst": dst,
                "ja3": ja3_hash,
                "threat": threat if threat else "Benign"
            }

            print("[JA3]", data, flush=True)

            # Store alert
            alerts.append(data)

            # Keep last 50 only
            if len(alerts) > 50:
                alerts.pop(0)

        except Exception as e:
            print("[ERROR]", e)
            continue


# ---------- API ----------
@app.get("/")
def root():
    return {"message": "Backend is Running"}


@app.get("/alerts")
def get_alerts():
    return jsonify(alerts)


# ---------- Main ----------
if __name__ == "__main__":
    t = threading.Thread(target=capture_packets)
    t.daemon = True
    t.start()

    app.run(host="0.0.0.0", port=5000)

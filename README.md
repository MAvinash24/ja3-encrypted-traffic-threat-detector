#  JA3 Encrypted Traffic Threat Detector

A real-time network security system that detects malicious activity in encrypted traffic using **JA3 TLS fingerprinting**, without decrypting payloads.

---

##  Features

*  Live TLS traffic capture (PyShark + Tshark)
*  Real JA3 fingerprint extraction
*  Threat detection using known fingerprint database
*  Real-time dashboard (React)
*  No decryption required (privacy-preserving)

---

##  Architecture

Frontend (React) → Backend (Flask API) → Live Packet Capture → JA3 Detection

---

##  Project Structure

```
ja3-threat-detector/
│
├── backend/
│   ├── app.py
│   ├── ja3.py
│   ├── threat_db.py
│   ├── fingerprints.json
│   ├── requirements.txt
│
├── frontend/
│   ├── src/
│   ├── package.json
│   ├── vite.config.js
│
└── README.md
```

---

## ⚙️ Requirements

* Ubuntu / Kali / Debian (recommended)
* Python 3.x
* Node.js (v20+ recommended)
* Tshark

---

##  Backend Setup (Ubuntu / Kali / Debian)

```bash
sudo apt update
sudo apt install -y python3 python3-pip tshark
```

### Create virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### Install dependencies

```bash
pip3 install -r requirements.txt
pip3 install flask-cors
```

### Run backend

```bash
sudo venv/bin/python app.py
```

---

##  Frontend Setup

### Install Node.js (if not installed)

```bash
sudo apt install npm
```

### Verify versions

```bash
node -v
npm -v
```

Expected:

```
v20.x.x
10.x.x
```

---

### Install dependencies

```bash
npm install
npm install axios
```

---

### Run frontend

```bash
npm run dev -- --host
```

---

## 🌍 Access Dashboard

Open in browser:

```
http://<your-ip>:5173
```

Example:

```
http://192.xxx.xxx.xxx:5173
```

---

##  API Endpoint

```
http://<your-ip>:5000/alerts
```

---

##  Demo

1. Start backend
2. Start frontend
3. Generate traffic:

```bash
curl https://google.com
```

4. Watch live JA3 fingerprints on dashboard

---

## 🧠 How It Works

* Captures TLS handshake packets
* Extracts JA3 fingerprint:

```
Version,Ciphers,Extensions,Curves,Formats → MD5
```

* Matches against threat database
* Displays alerts in real-time

---

##  Use Cases

* SOC monitoring
* Malware detection in encrypted traffic
* Network forensics
* Zero-trust environments

---

##  Notes

* Requires root privileges for packet capture
* Works best on Linux (Ubuntu/Kali/Debian)

---

##  Future Enhancements

* JA4 fingerprinting
* ML-based anomaly detection
* GeoIP visualization
* Alert severity scoring
* Cloud deployment

---

##  Author

Avinash

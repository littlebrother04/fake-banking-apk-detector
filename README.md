# Fake Banking APK Detector

A lightweight tool to detect potentially **fake banking APKs** using rule-based analysis on APK metadata,
permissions, certificates, and YARA string scanning.

---

## 🚀 Features
- Extracts APK metadata (package name, certificates, permissions)
- Matches against **trusted bank certificates** (from `known_banks.yaml`)
- Applies rule-based scoring engine (`rules.py`)
- Scans APK with YARA signatures (`strings.yar`)
- Generates risk score and reasons

---

## 📂 Project Structure
```
├── src/
│   ├── scan_apk.py       # Entry point for scanning APKs
│   ├── rules.py          # Scoring logic
│   ├── features.py       # Feature extraction
│   ├── ui_app.py         # (Optional) frontend / UI
├── data/
│   ├── known_banks.yaml  # Trusted certificate fingerprints
│   ├── strings.yar       # YARA rules for phishing keywords
├── requirements.txt
└── README.md
```

---

## ⚙️ Setup Instructions

1. Clone this repository or download the source code.
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate   # On Linux/Mac
   venv\Scripts\activate    # On Windows
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## ▶️ Usage

To scan an APK:
```bash
python src/scan_apk.py path/to/app.apk
```

Example output:
```
Risk Score: 8
Reasons:
- Suspicious permission: SEND_SMS
- Certificate not in known banks list
```

---

## 🛠️ Tech Stack
- **Language**: Python 3.13.7
- **Libraries**:
  - apkutils3 (APK parsing)
  - PyYAML (trusted cert list)
  - yara-python (YARA rule scanning)
  - os, sys, re, json (Python built-ins)

---

## 📖 References & Credits
- Android Developer Docs (APK structure, permissions)
- Python Official Docs
- Apkutils3 & Androguard GitHub Repos
- YARA Project Documentation
- Community resources: StackOverflow, GitHub Discussions

---

## 🚧 Future Improvements
- Train ML model on APK dataset for higher accuracy
- Build a dashboard for report visualization
- Integrate VirusTotal API for cross-checking

---

👨‍💻 Developed for **CIIS Cybersecurity Hackathon 2025**
Problem Statement **Detecting Fake Banking APKs**

import os
import yaml
import hashlib
from androguard.core.apk import APK

# Suspicious permissions that fake banking apps often request
SUSPICIOUS_PERMISSIONS = {
    "android.permission.RECEIVE_SMS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.READ_CALL_LOG",
    "android.permission.PACKAGE_USAGE_STATS"
}

def signer_sha256(apk: APK):
    """Extract SHA256 of APK signing cert"""
    certs = apk.get_certificates_der_v3() or apk.get_certificates_der_v2() or apk.get_certificates_der_v1()
    if not certs:
        return ""
    return hashlib.sha256(certs[0]).hexdigest().upper()

def load_banks(path="data/known_banks.yaml"):
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return yaml.safe_load(f)

def score(apk_features, known_banks=None):
    # Defensive default: make known_banks an iterable
    if known_banks is None:
        known_banks = []
    known_banks = set(known_banks)

    risk_score = 0
    reasons = []

    # Certificates: normalize to list
    certs = apk_features.get("cert_sha256", [])
    if certs is None:
        certs = []
    elif not isinstance(certs, list):
        certs = [certs] if certs else []

    # Rule: any cert not in known_banks -> suspicious
    if certs and any(cert not in known_banks for cert in certs):
        risk_score += 5
        reasons.append("Certificate not in known banks list")

    # Rule 3: package name contains 'bank' but none of the certs are trusted
    package = apk_features.get("package", "")
    # if package claims to be a bank and no cert matches known banks -> suspicious
    if "bank" in package.lower() and not any(cert in known_banks for cert in certs):
        risk_score += 3
        reasons.append("App claims to be a bank but cert not trusted")

    return risk_score, reasons


    # Rule 3: Check if package name looks strange
    package = apk_features.get("package", "")
    if "bank" in package.lower() and apk_features.get("cert_sha256") not in known_banks:
        score_value += 3
        reasons.append("App claims to be a bank but cert not trusted")

    return score_value, reasons

from androguard.core.apk import APK

import re, math
from collections import Counter

# Permissions we consider risky
DANGEROUS_PERMS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.READ_CALL_LOG",
    "android.permission.PACKAGE_USAGE_STATS"
}

# Regex to find URLs and IPs
URL_RE = re.compile(r'https?://[^\s"\'<>]+', re.I)
IP_RE  = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

def shannon_entropy(s):
    """Calculate entropy of a string (higher = more obfuscation)."""
    if not s:
        return 0
    p, n = Counter(s), float(len(s))
    return -sum((c/n) * math.log2(c/n) for c in p.values())

def extract_features(apk):
    try:
        features = {
            "permissions": apk.get_permissions() or [],
            "activities": apk.get_activities() or [],
            "services": apk.get_services() or [],
            "receivers": apk.get_receivers() or [],
            "providers": apk.get_providers() or [],
            # Always return a list, never None
            "cert_sha256": apk.get_signature_names() or []
        }
        return features
    except Exception as e:
        print(f"[ERROR] Failed to extract features: {e}")
        return {}




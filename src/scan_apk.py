import sys
from androguard.core.apk import APK
from features import extract_features
from rules import load_banks, score

def main(apk_path):
    # Load APK
    apk = APK(apk_path)
    features = extract_features(apk)   # ✅ pass the APK object, not the path

    # Load known banks
    known_banks = load_banks()

    # Run scoring rules
    risk_score, reasons = score(features, known_banks)

    # Print report
    print("=" * 50)
    print(f"📱 APK Scan Report for: {features.get('app_name')} ({features.get('package')})")
    print("=" * 50)
    print(f"🔑 Signing Cert SHA256: {features.get('cert_sha256')}")
    print(f"📊 Risk Score: {risk_score}")
    print("\n🔍 Reasons:")
    if reasons:
        for r in reasons:
            print(f"  - {r}")
    else:
        print("  ✅ No suspicious indicators found")
    print("=" * 50)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python src/scan_apk.py <apk_file>")
    else:
        main(sys.argv[1])

    

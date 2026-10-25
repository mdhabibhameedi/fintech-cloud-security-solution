"""Modular Assignment 4: minimal AWS KMS + JWT + RBAC security demonstration."""
import argparse
import csv
import json
import os
from collections import Counter
from pathlib import Path

import boto3
import jwt
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet

BASE = Path(__file__).resolve().parent
ROLES = {"viewer": {"read"}, "analyst": {"read", "analyze"}, "admin": {"read", "analyze", "manage"}}


def jwt_demo():
    secret = os.environ.get("DEMO_JWT_SECRET")
    if not secret or len(secret) < 32:
        raise RuntimeError("Set DEMO_JWT_SECRET to a random value of at least 32 characters")
    token = jwt.encode({"sub": "demo-viewer", "role": "viewer", "iss": "m4-demo", "aud": "m4-api", "exp": __import__("time").time() + 300}, secret, algorithm="HS256")
    claims = jwt.decode(token, secret, algorithms=["HS256"], issuer="m4-demo", audience="m4-api")
    print("JWT VALID:", claims["sub"], "role:", claims["role"])
    print("RBAC read:", "ALLOW" if "read" in ROLES[claims["role"]] else "DENY")
    print("RBAC manage:", "ALLOW" if "manage" in ROLES[claims["role"]] else "DENY")
    try:
        jwt.decode(token + "tampered", secret, algorithms=["HS256"], issuer="m4-demo", audience="m4-api")
        print("Tampered token: UNEXPECTED ACCEPT")
    except jwt.InvalidTokenError:
        print("Tampered token: REJECTED")


def analyze_logs():
    logs = json.loads((BASE / "Threat_Log.json").read_text())
    failures = Counter(e["ip"] for e in logs if e["event"] == "login_failed")
    alerts = []
    for ip, count in failures.items():
        if count >= 3:
            alerts.append({"threat": "Repeated failed login", "ip": ip, "count": count, "mitigation": "Rate-limit / temporary block recommended"})
    for event in logs:
        if event["event"] in ("access_denied", "suspicious_payload"):
            alerts.append({"threat": event["event"], "ip": event["ip"], "count": 1, "mitigation": "RBAC denial" if event["event"] == "access_denied" else "Input validation / WAF recommended"})
    print("\nTHREAT DASHBOARD (simulated log analysis)")
    print("Events:", len(logs), "| Alerts:", len(alerts))
    for alert in alerts:
        print(f"- {alert['threat']} | IP {alert['ip']} | occurrences {alert['count']} | {alert['mitigation']}")
    (BASE / "Threat_Analysis.json").write_text(json.dumps(alerts, indent=2) + "\n")


def kms_demo(key_id):
    if not key_id:
        print("\nKMS: SKIPPED (pass --kms-key-id with your AWS KMS key ARN or alias)")
        return
    client = boto3.client("kms")
    with (BASE / "Customer_Transactions.csv").open(newline="") as f:
        rows = list(csv.DictReader(f))
    sample = json.dumps(rows[0], sort_keys=True).encode()
    # AWS KMS directly encrypts a small sample record (not the whole CSV).
    encrypted = client.encrypt(KeyId=key_id, Plaintext=sample)["CiphertextBlob"]
    decrypted = client.decrypt(CiphertextBlob=encrypted, KeyId=key_id)["Plaintext"]
    print("\nAWS KMS encrypted sample transaction:", len(encrypted), "ciphertext bytes")
    print("AWS KMS decryption matches original:", decrypted == sample)
    assert decrypted == sample


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kms-key-id", default=os.environ.get("KMS_KEY_ID"))
    args = parser.parse_args()
    jwt_demo()
    analyze_logs()
    kms_demo(args.kms_key_id)


if __name__ == "__main__":
    main()

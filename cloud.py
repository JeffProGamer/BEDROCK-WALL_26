import json
import os
from typing import Optional

try:
    import firebase_admin
    from firebase_admin import credentials, firestore
except Exception:  # pragma: no cover - optional dependency
    firebase_admin = None
    credentials = None
    firestore = None


def _get_firestore_client():
    if firebase_admin is None or credentials is None or firestore is None:
        return None
    if not os.path.exists("firebase_key.json"):
        return None
    try:
        firebase_admin.initialize_app(credentials.Certificate("firebase_key.json"), name="bedrock-wall")
    except ValueError:
        pass
    return firestore.client(app=firebase_admin.get_app(name="bedrock-wall"))


def upload_scan_result(filename: str, status: str) -> None:
    db = _get_firestore_client()
    if db is None:
        return
    db.collection("scans").add({
        "filename": filename,
        "status": status,
    })
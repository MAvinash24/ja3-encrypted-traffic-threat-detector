import json

def load_db():
    with open("fingerprints.json") as f:
        return json.load(f)

def check_threat(ja3_hash):
    db = load_db()
    return db.get(ja3_hash, None)
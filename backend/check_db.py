import sqlite3
import json
import logging
from pathlib import Path

DB_FILE = "scans.db"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_connection():
    if not Path(DB_FILE).exists():
        raise FileNotFoundError(f"Database file '{DB_FILE}' not found.")
    return sqlite3.connect(DB_FILE)


def fetch_all_scans():
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()


def print_scan(row):
    try:
        findings = json.loads(row["findings"]) if row["findings"] else []
        recommendations = json.loads(row["recommendations"]) if row["recommendations"] else []
    except json.JSONDecodeError:
        findings = ["⚠ Corrupted JSON"]
        recommendations = ["⚠ Corrupted JSON"]

    print("=" * 60)
    print(f"ID: {row['id']}")
    print(f"Device IP: {row['device_ip']}")
    print(f"OS Type: {row['os_type']}")
    print(f"Username: {row['username']}")
    print(f"Scan Date: {row['scan_date']}")
    print(f"Threat Score: {row['threat_score']}")
    print(f"Threat Category: {row['threat_category']}")
    print("-" * 40)

    print("Findings:")
    for item in findings:
        print(f"  • {item}")

    print("\nRecommendations:")
    for item in recommendations:
        print(f"  • {item}")

    print("=" * 60)
    print()


def main():
    try:
        scans = fetch_all_scans()

        if not scans:
            print("No scans found.")
            return

        for row in scans:
            print_scan(row)

    except Exception as e:
        logger.exception("Error reading database")
        print("An error occurred while reading the database.")


if __name__ == "__main__":
    main()


import sqlite3

DB_NAME = "sentinel.db"

RULES = {
    ("System", 7040): {
        "severity": "LOW",
        "title": "Service configuration changed",
        "description": (
            "Konfigurasi startup service berubah. "
            "Perubahan ini belum tentu berbahaya. "
            "Periksa nama service dan konteks waktunya."
        )
    },

    ("Security", 1102): {
        "severity": "HIGH",
        "title": "Security audit log cleared",
        "description": (
            "Windows melaporkan Security Audit Log dibersihkan. "
            "Periksa apakah tindakan ini diotorisasi."
        )
    }
}


def run_detection():
    conn = sqlite3.connect(DB_NAME)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER,
            severity TEXT,
            title TEXT,
            description TEXT,
            status TEXT DEFAULT 'OPEN',
            UNIQUE(event_id, title)
        )
    """)

    events = conn.execute("""
        SELECT id, log_name, event_id, provider
        FROM events
    """).fetchall()

    detected = 0

    for row_id, log_name, windows_event_id, provider in events:
        rule = RULES.get((log_name, windows_event_id))

        if rule is None:
            continue

        description = (
            rule["description"]
            + f" Provider: {provider or 'Unknown'}."
            + f" Windows Event ID: {windows_event_id}."
            + f" Log: {log_name}."
        )

        cursor = conn.execute("""
            INSERT OR IGNORE INTO alerts
            (event_id, severity, title, description)
            VALUES (?, ?, ?, ?)
        """, (
            row_id,
            rule["severity"],
            rule["title"],
            description
        ))

        detected += cursor.rowcount

    conn.commit()

    alerts = conn.execute("""
        SELECT severity, title, description, status
        FROM alerts
        ORDER BY id DESC
    """).fetchall()

    print("\n=== SENTINEL X DETECTION ENGINE ===")
    print("Event diperiksa:", len(events))
    print("Alert baru:", detected)
    print("Total alert:", len(alerts))

    for alert in alerts:
        print("\nSeverity:", alert[0])
        print("Judul:", alert[1])
        print("Keterangan:", alert[2])
        print("Status:", alert[3])

    conn.close()


if __name__ == "__main__":
    run_detection()

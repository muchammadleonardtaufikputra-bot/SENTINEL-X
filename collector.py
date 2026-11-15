
import subprocess
import json
import sqlite3
import tempfile
from pathlib import Path
from datetime import datetime

DB_NAME = "sentinel.db"
LOG_NAMES = ("System", "Security")
BATCH_SIZE = 100
TIMEOUT_SECONDS = 30


def init_database():
    conn = sqlite3.connect(DB_NAME)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_name TEXT,
            record_id INTEGER,
            event_id INTEGER,
            provider TEXT,
            level TEXT,
            event_time TEXT,
            collected_at TEXT,
            UNIQUE(log_name, record_id)
        )
    """)

    conn.commit()
    return conn


def collect_log_events(conn, log_name):
    last_record = conn.execute("""
        SELECT COALESCE(MAX(record_id), 0)
        FROM events
        WHERE log_name = ?
    """, (log_name,)).fetchone()[0]

    if last_record == 0:
        command = (
            f'Get-WinEvent -LogName "{log_name}" '
            f'-MaxEvents {BATCH_SIZE} -ErrorAction Stop'
        )
    else:
        command = (
            f'Get-WinEvent -LogName "{log_name}" '
            f'-FilterXPath "*[System[EventRecordID > {last_record}]]" '
            f'-Oldest -MaxEvents {BATCH_SIZE} -ErrorAction Stop'
        )

    script = f"""
        $ErrorActionPreference = "Stop"

        try {{
            $events = @({command})

            if ($events.Count -gt 0) {{
                $events |
                Select-Object LogName, RecordId, Id, ProviderName,
                    LevelDisplayName,
                    @{{Name="TimeCreated";Expression={{$_.TimeCreated.ToString("o")}}}} |
                ConvertTo-Json -Depth 3 -Compress
            }}
        }}
        catch {{
            if ($_.FullyQualifiedErrorId -like "*NoMatchingEventsFound*") {{
                exit 0
            }}

            [Console]::Error.WriteLine($_.ToString())
            exit 1
        }}
    """

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / "output.json"
            error_file = Path(temp_dir) / "error.txt"

            with open(output_file, "w", encoding="utf-8") as out, \
                 open(error_file, "w", encoding="utf-8") as err:

                result = subprocess.run(
                    [
                        "powershell.exe",
                        "-NoProfile",
                        "-Command",
                        script
                    ],
                    stdout=out,
                    stderr=err,
                    timeout=TIMEOUT_SECONDS
                )

            output = output_file.read_text(
                encoding="utf-8-sig"
            ).strip()

            error = error_file.read_text(
                encoding="utf-8-sig"
            ).strip()

    except subprocess.TimeoutExpired:
        print(f"Timeout saat membaca {log_name}.")
        return 0, 0

    except OSError as exc:
        print(f"Kesalahan sistem saat membaca {log_name}: {exc}")
        return 0, 0

    if result.returncode != 0:
        print(f"Gagal membaca {log_name}:")
        print(error or "Kesalahan PowerShell.")
        return 0, 0

    if not output:
        events = []
    else:
        try:
            events = json.loads(output)

            if isinstance(events, dict):
                events = [events]

        except json.JSONDecodeError:
            print(f"JSON tidak valid dari {log_name}.")
            return 0, 0

    events.sort(key=lambda event: event.get("RecordId", 0))

    saved = 0

    for event in events:
        cursor = conn.execute("""
            INSERT OR IGNORE INTO events
            (log_name, record_id, event_id, provider,
             level, event_time, collected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            event.get("LogName"),
            event.get("RecordId"),
            event.get("Id"),
            event.get("ProviderName"),
            event.get("LevelDisplayName"),
            event.get("TimeCreated"),
            datetime.now().isoformat(timespec="seconds")
        ))

        saved += cursor.rowcount

    conn.commit()

    print(f"\nLog: {log_name}")
    print("Event diperiksa:", len(events))
    print("Event baru disimpan:", saved)
    print("Record ID terakhir sebelumnya:", last_record)

    return len(events), saved


def collect_system_events():
    conn = init_database()

    total_checked = 0
    total_saved = 0

    for log_name in LOG_NAMES:
        checked, saved = collect_log_events(conn, log_name)

        total_checked += checked
        total_saved += saved

    total = conn.execute(
        "SELECT COUNT(*) FROM events"
    ).fetchone()[0]

    print("\n================================")
    print("       SENTINEL X COLLECTOR")
    print("================================")
    print("Log dipantau:", ", ".join(LOG_NAMES))
    print("Total diperiksa:", total_checked)
    print("Event baru:", total_saved)
    print("Total database:", total)
    print("Status: SELESAI")
    print("================================")

    conn.close()


if __name__ == "__main__":
    collect_system_events()

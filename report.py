
import sqlite3
import csv
import os
from datetime import datetime

DB_NAME = "sentinel.db"
REPORT_DIR = "reports"

SECURITY_EVENT_INFO = {
    4624: (
        "Successful Logon",
        "A user successfully signed in to Windows."
    ),
    4648: (
        "Explicit Credentials",
        "A logon attempt used explicitly supplied credentials."
    ),
    4672: (
        "Special Privileges Assigned",
        "Special privileges were assigned to a new logon."
    ),
    4798: (
        "Local Group Enumeration",
        "A process queried a user's local group membership."
    ),
    4907: (
        "Auditing Settings Changed",
        "Auditing settings on an object were changed."
    ),
    5379: (
        "Credential Manager Access",
        "Credential Manager credentials were read."
    )
}


def write_section(writer, title, headers, rows):
    writer.writerow([])
    writer.writerow([title])
    writer.writerow(headers)

    for row in rows:
        writer.writerow(row)


def create_report():

    if not os.path.exists(DB_NAME):
        print("Database sentinel.db tidak ditemukan.")
        return

    os.makedirs(REPORT_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    filename = os.path.join(
        REPORT_DIR,
        f"SENTINEL_X_Professional_Report_{timestamp}.csv"
    )

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row

    try:
        # 1. Executive Summary
        total_events = conn.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]

        total_alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        total_history = conn.execute(
            "SELECT COUNT(*) FROM alert_history"
        ).fetchone()[0]

        # 2. Event Source Summary
        source_counts = conn.execute("""
            SELECT log_name, COUNT(*) AS total
            FROM events
            GROUP BY log_name
        """).fetchall()

        source_map = {
            row["log_name"]: row["total"]
            for row in source_counts
        }

        system_events = source_map.get("System", 0)
        security_events = source_map.get("Security", 0)

        # 3. Alert Severity
        severity_counts = conn.execute("""
            SELECT UPPER(severity) AS severity, COUNT(*) AS total
            FROM alerts
            GROUP BY UPPER(severity)
        """).fetchall()

        severity_map = {
            row["severity"]: row["total"]
            for row in severity_counts
        }

        # 4. Alert Status
        status_counts = conn.execute("""
            SELECT UPPER(status) AS status, COUNT(*) AS total
            FROM alerts
            GROUP BY UPPER(status)
        """).fetchall()

        status_map = {
            row["status"]: row["total"]
            for row in status_counts
        }

        # 5. Security Event Insights
        security_counts = conn.execute("""
            SELECT event_id, COUNT(*) AS total
            FROM events
            WHERE log_name = 'Security'
            GROUP BY event_id
        """).fetchall()

        security_map = {
            row["event_id"]: row["total"]
            for row in security_counts
        }

        # 6. Alert Details
        alerts = conn.execute("""
            SELECT
                alerts.id,
                alerts.severity,
                alerts.title,
                alerts.description,
                alerts.status,
                events.log_name,
                events.event_id AS windows_event_id,
                events.provider,
                events.level,
                events.event_time
            FROM alerts
            LEFT JOIN events
                ON events.id = alerts.event_id
            ORDER BY alerts.id DESC
        """).fetchall()

        # 7. Activity History
        history = conn.execute("""
            SELECT
                id,
                alert_id,
                alert_title,
                old_status,
                new_status,
                changed_at
            FROM alert_history
            ORDER BY id DESC
        """).fetchall()

        with open(
            filename,
            "w",
            newline="",
            encoding="utf-8-sig"
        ) as file:

            writer = csv.writer(file)

            writer.writerow(["SENTINEL X"])
            writer.writerow(["PROFESSIONAL SOC REPORT"])
            writer.writerow(["Generated At", generated_at])
            writer.writerow(["Database", DB_NAME])

            # Executive Summary
            write_section(
                writer,
                "1. EXECUTIVE SUMMARY",
                ["Metric", "Value"],
                [
                    ["Total Events", total_events],
                    ["Total Alerts", total_alerts],
                    ["System Events", system_events],
                    ["Security Events", security_events],
                    ["Alert History Records", total_history]
                ]
            )

            # Event Sources
            write_section(
                writer,
                "2. EVENT SOURCE SUMMARY",
                ["Log Source", "Event Count"],
                [
                    ["System", system_events],
                    ["Security", security_events]
                ]
            )

            # Severity
            write_section(
                writer,
                "3. ALERT SEVERITY SUMMARY",
                ["Severity", "Alert Count"],
                [
                    ["HIGH", severity_map.get("HIGH", 0)],
                    ["MEDIUM", severity_map.get("MEDIUM", 0)],
                    ["LOW", severity_map.get("LOW", 0)]
                ]
            )

            # Status
            write_section(
                writer,
                "4. ALERT STATUS SUMMARY",
                ["Status", "Alert Count"],
                [
                    ["OPEN", status_map.get("OPEN", 0)],
                    ["CLOSED", status_map.get("CLOSED", 0)]
                ]
            )

            # Security Insights
            insight_rows = []

            for event_id, info in SECURITY_EVENT_INFO.items():
                insight_rows.append([
                    event_id,
                    info[0],
                    security_map.get(event_id, 0),
                    info[1],
                    "Informational only; event count alone does not prove malicious activity."
                ])

            write_section(
                writer,
                "5. SECURITY EVENT INSIGHTS",
                [
                    "Windows Event ID",
                    "Event Name",
                    "Count",
                    "Description",
                    "Interpretation"
                ],
                insight_rows
            )

            # Alert Details
            alert_rows = [
                [
                    row["id"],
                    row["severity"],
                    row["title"],
                    row["description"],
                    row["status"],
                    row["log_name"],
                    row["windows_event_id"],
                    row["provider"],
                    row["level"],
                    row["event_time"]
                ]
                for row in alerts
            ]

            write_section(
                writer,
                "6. ALERT DETAILS",
                [
                    "Alert ID",
                    "Severity",
                    "Title",
                    "Description",
                    "Status",
                    "Log Source",
                    "Windows Event ID",
                    "Provider",
                    "Event Level",
                    "Event Time"
                ],
                alert_rows
            )

            # Activity History
            history_rows = [
                [
                    row["id"],
                    row["alert_id"],
                    row["alert_title"],
                    row["old_status"],
                    row["new_status"],
                    row["changed_at"]
                ]
                for row in history
            ]

            write_section(
                writer,
                "7. ACTIVITY HISTORY",
                [
                    "History ID",
                    "Alert ID",
                    "Alert Title",
                    "Previous Status",
                    "New Status",
                    "Changed At"
                ],
                history_rows
            )

            writer.writerow([])
            writer.writerow([
                "NOTE",
                "This report is generated from locally collected Windows events."
            ])
            writer.writerow([
                "DISCLAIMER",
                "Event IDs and counts alone do not establish malicious activity."
            ])

        print()
        print("================================")
        print(" SENTINEL X PROFESSIONAL REPORT")
        print("================================")
        print(f"Total Events       : {total_events}")
        print(f"Total Alerts       : {total_alerts}")
        print(f"System Events      : {system_events}")
        print(f"Security Events    : {security_events}")
        print(f"Activity Records   : {total_history}")
        print("--------------------------------")
        print(f"Report file        : {filename}")
        print("Status             : SUCCESS")
        print("================================")

    except (sqlite3.Error, OSError) as error:
        print("Report error:", error)

    finally:
        conn.close()


if __name__ == "__main__":
    create_report()

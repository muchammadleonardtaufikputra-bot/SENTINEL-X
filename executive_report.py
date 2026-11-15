
import sqlite3
import csv
import os
from datetime import datetime

DB_NAME = "sentinel.db"
REPORT_DIR = "reports"


def create_executive_report():
    if not os.path.exists(DB_NAME):
        print("Database sentinel.db tidak ditemukan.")
        return

    os.makedirs(REPORT_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(
        REPORT_DIR,
        f"SENTINEL_X_Executive_Report_{timestamp}.csv"
    )

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row

    try:
        total_events = conn.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]

        total_alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        event_sources = conn.execute("""
            SELECT log_name, COUNT(*) AS total
            FROM events
            GROUP BY log_name
        """).fetchall()

        severities = conn.execute("""
            SELECT severity, COUNT(*) AS total
            FROM alerts
            GROUP BY severity
        """).fetchall()

        statuses = conn.execute("""
            SELECT status, COUNT(*) AS total
            FROM alerts
            GROUP BY status
        """).fetchall()

        activity_total = conn.execute(
            "SELECT COUNT(*) FROM alert_history"
        ).fetchone()[0]

        security_events = conn.execute("""
            SELECT event_id, COUNT(*) AS total
            FROM events
            WHERE log_name = 'Security'
            GROUP BY event_id
            ORDER BY event_id
        """).fetchall()

        alert_details = conn.execute("""
            SELECT
                alerts.id,
                alerts.severity,
                alerts.title,
                alerts.status,
                events.log_name,
                events.event_id,
                events.provider,
                events.event_time
            FROM alerts
            LEFT JOIN events
                ON events.id = alerts.event_id
            ORDER BY alerts.id DESC
        """).fetchall()

        with open(
            filename,
            "w",
            newline="",
            encoding="utf-8-sig"
        ) as file:
            writer = csv.writer(file)

            writer.writerow(["SENTINEL X - EXECUTIVE SOC REPORT"])
            writer.writerow(["Generated At", datetime.now().isoformat()])
            writer.writerow([])

            writer.writerow(["EXECUTIVE SUMMARY"])
            writer.writerow(["Metric", "Value"])
            writer.writerow(["Total Events", total_events])
            writer.writerow(["Total Alerts", total_alerts])
            writer.writerow(["Activity Records", activity_total])
            writer.writerow([])

            writer.writerow(["EVENT SOURCE ANALYSIS"])
            writer.writerow(["Log Name", "Event Count"])

            for row in event_sources:
                writer.writerow([row["log_name"], row["total"]])

            writer.writerow([])
            writer.writerow(["ALERT SEVERITY"])
            writer.writerow(["Severity", "Count"])

            for row in severities:
                writer.writerow([row["severity"], row["total"]])

            writer.writerow([])
            writer.writerow(["ALERT STATUS"])
            writer.writerow(["Status", "Count"])

            for row in statuses:
                writer.writerow([row["status"], row["total"]])

            writer.writerow([])
            writer.writerow(["SECURITY EVENT INSIGHTS"])
            writer.writerow([
                "Windows Event ID",
                "Event Count",
                "Interpretation"
            ])

            descriptions = {
                4624: "Successful Logon",
                4648: "Explicit Credentials",
                4672: "Special Privileges Assigned",
                4798: "Local Group Enumeration",
                4907: "Auditing Settings Changed",
                5379: "Credential Manager Access"
            }

            security_counts = {
                row["event_id"]: row["total"]
                for row in security_events
            }

            for event_id, description in descriptions.items():
                writer.writerow([
                    event_id,
                    security_counts.get(event_id, 0),
                    description
                ])

            writer.writerow([])
            writer.writerow([
                "Informational analysis only. Event counts alone "
                "do not establish malicious activity."
            ])

            writer.writerow([])
            writer.writerow(["ALERT DETAILS"])
            writer.writerow([
                "Alert ID",
                "Severity",
                "Title",
                "Status",
                "Log Name",
                "Windows Event ID",
                "Provider",
                "Event Time"
            ])

            for alert in alert_details:
                writer.writerow([
                    alert["id"],
                    alert["severity"],
                    alert["title"],
                    alert["status"],
                    alert["log_name"],
                    alert["event_id"],
                    alert["provider"],
                    alert["event_time"]
                ])

        print()
        print("================================")
        print(" SENTINEL X EXECUTIVE REPORT")
        print("================================")
        print(f"Total Events    : {total_events}")
        print(f"Total Alerts    : {total_alerts}")
        print(f"Activity Records: {activity_total}")
        print(f"Report File     : {filename}")
        print("Status          : SUCCESS")
        print("================================")

    except (sqlite3.Error, OSError) as error:
        print("Report error:", error)

    finally:
        conn.close()


if __name__ == "__main__":
    create_executive_report()

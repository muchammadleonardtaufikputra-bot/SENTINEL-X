
import subprocess
import sys
import time

INTERVAL = 10

print("=== SENTINEL X AUTO MONITOR ===")
print("Monitoring berjalan setiap 10 detik.")
print("Tekan CTRL+C untuk berhenti.\n")

try:
    while True:
        print("Mengambil Windows Events...")

        subprocess.run(
            [sys.executable, "collector.py"],
            check=False
        )

        print("Menjalankan Detection Engine...")

        subprocess.run(
            [sys.executable, "detector.py"],
            check=False
        )

        print("Siklus selesai. Menunggu 10 detik...\n")
        time.sleep(INTERVAL)

except KeyboardInterrupt:
    print("\nSENTINEL X Monitoring dihentikan.")

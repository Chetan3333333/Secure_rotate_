import time
import sqlite3
import os
import sys

# Ensure we can import from app
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import refresh_notifications

def run_worker():
    print("Starting Automated Background Alerts Worker...")
    
    # Load .env
    if os.path.exists(".env"):
        print("Loaded .env file")
        with open(".env") as f:
            for line in f:
                if '=' in line and not line.strip().startswith('#'):
                    k, v = line.strip().split('=', 1)
                    os.environ[k] = v
                    
    print("Worker is now running. Press CTRL+C to stop.")
    
    while True:
        try:
            with sqlite3.connect("securerotate.db") as conn:
                conn.row_factory = sqlite3.Row
                # Scan for expiring credentials and dispatch emails
                refresh_notifications(conn)
        except Exception as e:
            print(f"Error in background worker: {e}")
        
        # Sleep for 60 seconds (in a real production app, this would be daily/hourly)
        time.sleep(60)

if __name__ == "__main__":
    run_worker()

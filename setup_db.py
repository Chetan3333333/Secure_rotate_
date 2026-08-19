import os
import mysql.connector
from dotenv import load_dotenv

load_dotenv()

try:
    # Connect without specifying the database
    conn = mysql.connector.connect(
        host=os.environ.get("MYSQL_HOST", "127.0.0.1"),
        port=int(os.environ.get("MYSQL_PORT", "3306")),
        user=os.environ.get("MYSQL_USER", "root"),
        password=os.environ.get("MYSQL_PASSWORD", "")
    )
    cursor = conn.cursor()
    db_name = os.environ.get("MYSQL_DATABASE", "securerotate")
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
    print(f"Database '{db_name}' is ready.")
    cursor.close()
    conn.close()
except mysql.connector.Error as err:
    if err.errno == 1045:
        print("\nERROR: MySQL Access Denied.")
        print("Please open the '.env' file and update MYSQL_PASSWORD with your actual MySQL root password.")
        exit(1)
    else:
        print(f"\nERROR: {err}")
        exit(1)

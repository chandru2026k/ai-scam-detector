from app.db.database import client

try:
    print(client.list_database_names())
    print("Connection successful!")
except Exception as e:
    print("Connection FAILED:", e)
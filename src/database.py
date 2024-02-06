from pymongo import MongoClient

import pymongo

from .config import settings


client = MongoClient(settings.DATABASE_URL, serverSelectionTimeoutMS=5000)


try:
    conn = client.server_info()
    print(f'Connected to MongoDB {conn.get("version")}')
except Exception:
    print("Unable to connect to the MongoDB server.")


db = client[settings.MONGO_INITDB_DATABASE]

users = db.users
users.create_index([("username", pymongo.ASCENDING)], unique=True)

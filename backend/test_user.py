# test_user.py - Script to create a test user in MongoDB
from pymongo import MongoClient
import bcrypt
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Connect to MongoDB
mongo_uri = os.getenv('MONGO_URI', 'mongodb://localhost:27017/chatapp')
client = MongoClient(mongo_uri)
db = client.chatapp

# Create a test user
username = "testuser"
password = "password123"

# Check if user exists and delete if it does
existing_user = db.users.find_one({'username': username})
if existing_user:
    db.users.delete_one({'username': username})
    print(f"Deleted existing user '{username}'")

# Hash password
hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Create new user
new_user = {
    'username': username,
    'password': hashed_password
}

result = db.users.insert_one(new_user)
print(f"Test user created with ID: {result.inserted_id}")

# Verify user can be retrieved and password checked
user = db.users.find_one({'username': username})
if user:
    print(f"Successfully retrieved user '{username}'")
    
    # Verify password check works
    is_valid = bcrypt.checkpw(password.encode('utf-8'), user['password'])
    print(f"Password verification: {'Success' if is_valid else 'Failed'}")
else:
    print("Error: Failed to retrieve user after creation")
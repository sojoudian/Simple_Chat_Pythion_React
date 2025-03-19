# server.py
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, join_room
from flask_cors import CORS
from pymongo import MongoClient
from bson.objectid import ObjectId
import bcrypt
import jwt
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from functools import wraps

# Load environment variables
load_dotenv()

app = Flask(__name__)
# Set up CORS properly to avoid duplicate headers
socketio = SocketIO(app, 
                   cors_allowed_origins=["http://localhost:3000"],
                   logger=True, 
                   engineio_logger=True)

# Connect to MongoDB
mongo_uri = os.getenv('MONGO_URI', 'mongodb://localhost:27017/chatapp')
client = MongoClient(mongo_uri)
db = client.chatapp

# JWT Secret
jwt_secret = os.getenv('JWT_SECRET', 'your_jwt_secret')

# User connection mapping
user_connections = {}

# Configure CORS to handle preflight requests and credentials
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3000')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Handle OPTIONS request for preflight CORS
        if request.method == 'OPTIONS':
            return jsonify({'status': 'success'})
            
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header:
            token = auth_header.split(" ")[1]
            
        if not token:
            return jsonify({'message': 'Access denied'}), 401
            
        try:
            payload = jwt.decode(token, jwt_secret, algorithms=["HS256"])
            request.user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expired'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 403
            
        return f(*args, **kwargs)
    return decorated

# Authentication Routes
@app.route('/api/register', methods=['POST', 'OPTIONS'])
def register():
    # Handle preflight OPTIONS request
    if request.method == 'OPTIONS':
        return jsonify({'status': 'success'})
        
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        # Check if user already exists
        existing_user = db.users.find_one({'username': username})
        if existing_user:
            return jsonify({'message': 'Username already taken'}), 400
        
        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Create new user
        new_user = {
            'username': username,
            'password': hashed_password
        }
        
        result = db.users.insert_one(new_user)
        
        # Create JWT token
        token = jwt.encode(
            {
                'id': str(result.inserted_id),
                'username': username,
                'exp': datetime.utcnow() + timedelta(hours=24)
            },
            jwt_secret,
            algorithm="HS256"
        )
        
        return jsonify({
            'message': 'User registered successfully',
            'token': token,
            'username': username
        }), 201
    
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'message': 'Server error'}), 500

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    # Handle preflight OPTIONS request
    if request.method == 'OPTIONS':
        return jsonify({'status': 'success'})
        
    try:
        # Detailed logging for debugging
        print("Login attempt received")
        
        # Check if we're getting JSON data
        if not request.is_json:
            print("Error: Request is not JSON")
            return jsonify({'message': 'Request must be JSON'}), 400
            
        data = request.get_json()
        print(f"Request data received: {data}")
        
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            print("Error: Missing username or password")
            return jsonify({'message': 'Username and password are required'}), 400
        
        # Find user
        print(f"Looking up user: {username}")
        user = db.users.find_one({'username': username})
        
        if not user:
            print(f"User not found: {username}")
            return jsonify({'message': 'Invalid username or password'}), 400
        
        print("User found, checking password...")
        
        # Check if password field exists in user document
        if not user.get('password'):
            print("Error: User has no password field")
            return jsonify({'message': 'User account is invalid'}), 400
            
        # Make sure password is bytes for bcrypt
        if isinstance(user['password'], str):
            stored_password = user['password'].encode('utf-8')
        else:
            stored_password = user['password']
            
        # Check password
        try:
            # Debug password data types
            print(f"Password type: {type(password)}")
            print(f"Stored password type: {type(stored_password)}")
            
            is_match = bcrypt.checkpw(password.encode('utf-8'), stored_password)
            print(f"Password match: {is_match}")
            
            if not is_match:
                return jsonify({'message': 'Invalid username or password'}), 400
                
        except Exception as pw_err:
            print(f"Password check error: {pw_err}")
            return jsonify({'message': 'Authentication error'}), 400
        
        # Create JWT token
        print("Creating JWT token")
        token = jwt.encode(
            {
                'id': str(user['_id']),
                'username': user['username'],
                'exp': datetime.utcnow() + timedelta(hours=24)
            },
            jwt_secret,
            algorithm="HS256"
        )
        
        print("Login successful")
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'username': user['username']
        })
    
    except Exception as e:
        import traceback
        print(f"Login error: {e}")
        print(traceback.format_exc())  # Print full traceback for debugging
        return jsonify({'message': f'Server error: {str(e)}'}), 500

# Message Routes
@app.route('/api/messages/<recipient>', methods=['GET', 'OPTIONS'])
@token_required
def get_messages(recipient):
    try:
        sender = request.user['username']
        
        # Get messages between users (in both directions)
        messages = list(db.messages.find({
            '$or': [
                {'sender': sender, 'recipient': recipient},
                {'sender': recipient, 'recipient': sender}
            ]
        }).sort('timestamp', 1))
        
        # Convert ObjectId to string for JSON serialization
        for message in messages:
            message['_id'] = str(message['_id'])
        
        return jsonify(messages)
    
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'message': 'Server error'}), 500

# Get all users
@app.route('/api/users', methods=['GET', 'OPTIONS'])
@token_required
def get_users():
    try:
        users = list(db.users.find({}, {'username': 1, '_id': 0}))
        return jsonify(users)
    
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'message': 'Server error'}), 500

# Socket.io connection
@socketio.on('connect')
def handle_connect():
    print('New client connected')
    # Send a connection acknowledgement
    socketio.emit('connection_established', {'status': 'connected'}, room=request.sid)

@socketio.on('authenticate')
def handle_authenticate(token):
    try:
        print(f"Authentication attempt with token: {token[:10]}...")
        payload = jwt.decode(token, jwt_secret, algorithms=["HS256"])
        username = payload['username']
        
        # Store user info in the session
        request.sid = request.sid  # Store socket ID
        
        # Join a room with their username
        join_room(username)
        user_connections[request.sid] = payload
        print(f"User {username} authenticated successfully")
        
        # Send authentication confirmation
        socketio.emit('authenticated', {'status': 'success', 'username': username}, room=request.sid)
    
    except Exception as e:
        print(f"Socket authentication failed: {e}")
        socketio.emit('authentication_failed', {'status': 'error', 'message': str(e)}, room=request.sid)

@socketio.on('send_message')
def handle_send_message(data):
    try:
        if request.sid not in user_connections:
            return
        
        user = user_connections[request.sid]
        sender = user['username']
        recipient = data.get('recipient')
        content = data.get('content')
        
        # Save message to database
        timestamp = datetime.utcnow()
        new_message = {
            'sender': sender,
            'recipient': recipient,
            'content': content,
            'timestamp': timestamp
        }
        
        result = db.messages.insert_one(new_message)
        
        # Send message to recipient if they're online
        socketio.emit('receive_message', {
            'sender': sender,
            'content': content,
            'timestamp': timestamp
        }, room=recipient)
        
        # Also send confirmation back to sender
        socketio.emit('message_sent', {
            'id': str(result.inserted_id),
            'recipient': recipient,
            'content': content,
            'timestamp': timestamp
        }, room=request.sid)
    
    except Exception as e:
        print(f"Error sending message: {e}")

@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in user_connections:
        del user_connections[request.sid]
    print('Client disconnected')

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5001))
    print(f"Server running on port {port}")
    
    # Configure socket.io for compatibility with newer Flask-SocketIO versions
    socketio.run(app, 
                 host='0.0.0.0', 
                 port=port, 
                 debug=True,
                 allow_unsafe_werkzeug=True)  # Required for development

# Create a .env file in your project root with:
# MONGO_URI=mongodb://localhost:27017/chatapp
# JWT_SECRET=test_secret_this_is_for_academic_purposes
# PORT=5001
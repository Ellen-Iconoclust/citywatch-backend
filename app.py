# app.py (updated with better security practices)
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
import uuid
from geopy.geocoders import Nominatim
from PIL import Image
import io
import jwt  # Add this import
from functools import wraps  # Add this import

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-insecure-key-for-dev-only')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Enable CORS with stricter settings for production
if os.environ.get('FLASK_ENV') == 'production':
    CORS(app, origins=[os.environ.get('FRONTEND_URL', 'https://yourusername.github.io')])
else:
    CORS(app)

# JWT Token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = next((u for u in users if u['id'] == data['user_id']), None)
            if not current_user:
                return jsonify({'error': 'Invalid token'}), 401
        except:
            return jsonify({'error': 'Token is invalid'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

# Your existing routes and functions below...

# Updated login function to use JWT
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"error": "Email and password required"}), 400
    
    user = next((u for u in users if u['email'] == data['email']), None)
    
    if not user or not check_password_hash(user['password_hash'], data['password']):
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Generate JWT token
    token = jwt.encode({
        'user_id': user['id'],
        'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
    }, app.config['SECRET_KEY'])
    
    return jsonify({
        "message": "Login successful",
        "token": token,
        "user": {
            "id": user['id'],
            "name": user['name'],
            "email": user['email'],
            "role": user['role']
        }
    })

# Updated admin login function
@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    
    if not data or not data.get('admin_id') or not data.get('department') or not data.get('code'):
        return jsonify({"error": "Admin credentials required"}), 400
    
    # For demo purposes - in real app, verify against secure database
    if data['admin_id'] == 'admin123' and data['code'] == 'secure2024':
        admin_user = next((u for u in users if u['role'] == 'admin'), None)
        
        if admin_user:
            # Generate JWT token
            token = jwt.encode({
                'user_id': admin_user['id'],
                'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
            }, app.config['SECRET_KEY'])
            
            return jsonify({
                "message": "Admin login successful",
                "token": token,
                "user": {
                    "id": admin_user['id'],
                    "name": admin_user['name'],
                    "email": admin_user['email'],
                    "role": admin_user['role'],
                    "department": data['department']
                }
            })
    
    return jsonify({"error": "Invalid admin credentials"}), 401

# Example of protected route
@app.route('/api/admin/issues', methods=['GET'])
@token_required
@admin_required
def admin_issues_list(current_user):
    # This route now requires a valid admin token
    status_filter = request.args.get('status', '')
    
    filtered_issues = issues
    if status_filter:
        filtered_issues = [i for i in issues if i['status'] == status_filter]
    
    return jsonify({
        "issues": filtered_issues,
        "total": len(filtered_issues)
    })

if __name__ == '__main__':
    # Check if SECRET_KEY is the default (insecure)
    if app.config['SECRET_KEY'] == 'fallback-insecure-key-for-dev-only':
        print("⚠️  WARNING: Using default SECRET_KEY. This is insecure for production!")
        print("⚠️  Set a secure SECRET_KEY environment variable")
    
    app.run(debug=os.environ.get('FLASK_ENV') != 'production', host='0.0.0.0', port=5000)

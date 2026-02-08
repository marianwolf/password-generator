#!/usr/bin/env python3
# ============================================
# Password Vault - Flask Backend Application
# ============================================
# Secure password management API with JWT authentication

import os
import logging
import secrets
import string
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.security import secure_filename
from cryptography.fernet import Fernet
from marshmallow import Schema, fields, validate, ValidationError
from sqlalchemy import event, desc
from sqlalchemy.engine import Engine
from sqlite3 import DatabaseError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/app/logs/vault.log')
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.environ.get('DATABASE_PATH', '/app/data/vault.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300
}

# Enable CORS
CORS(app, resources={
    r"/api/*": {
        "origins": os.environ.get('ALLOWED_ORIGINS', '*').split(','),
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Initialize encryption
def get_encryption_key():
    """Retrieve or generate encryption key."""
    key = os.environ.get('ENCRYPTION_KEY')
    if not key:
        logger.warning("No ENCRYPTION_KEY set, using generated key (not recommended for production)")
        key = Fernet.generate_key().decode()
    return key

cipher_suite = Fernet(get_encryption_key().encode())

# ============================================
# SQL Injection Protection
# ============================================
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_conn, connection_record):
    """Set SQLite pragmas for security."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

# ============================================
# Database Models
# ============================================
class User(db.Model):
    """User model for authentication."""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    master_password_hash = db.Column(db.String(255), nullable=False)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    passwords = db.relationship('PasswordEntry', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    sessions = db.relationship('UserSession', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set user password."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify user password."""
        return check_password_hash(self.password_hash, password)
    
    def set_master_password(self, master_password):
        """Hash and set master password."""
        self.master_password_hash = generate_password_hash(master_password)
    
    def check_master_password(self, master_password):
        """Verify master password."""
        return check_password_hash(self.master_password_hash, master_password)
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'email': self.email,
            'two_factor_enabled': self.two_factor_enabled,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

class UserSession(db.Model):
    """Session model for secure session management."""
    __tablename__ = 'user_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    device_info = db.Column(db.String(500), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_activity = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
    def is_valid(self):
        """Check if session is valid."""
        return self.is_active and datetime.now(timezone.utc) < self.expires_at
    
    def update_activity(self):
        """Update last activity timestamp."""
        self.last_activity = datetime.now(timezone.utc)
        db.session.commit()
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'device_info': self.device_info,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_activity': self.last_activity.isoformat() if self.last_activity else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }

class PasswordEntry(db.Model):
    """Password entry model with encrypted storage."""
    __tablename__ = 'password_entries'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=True)
    encrypted_password = db.Column(db.Text, nullable=False)
    website_url = db.Column(db.String(500), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), default='other')
    is_favorite = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    last_accessed = db.Column(db.DateTime, nullable=True)
    password_strength = db.Column(db.Integer, nullable=True)
    expiry_date = db.Column(db.DateTime, nullable=True)
    
    def encrypt_password(self, password):
        """Encrypt password using Fernet symmetric encryption."""
        self.encrypted_password = cipher_suite.encrypt(password.encode()).decode()
    
    def decrypt_password(self):
        """Decrypt password."""
        try:
            return cipher_suite.decrypt(self.encrypted_password.encode()).decode()
        except Exception as e:
            logger.error(f"Failed to decrypt password: {e}")
            return None
    
    def to_dict(self, include_password=False):
        """Convert to dictionary."""
        data = {
            'id': self.id,
            'title': self.title,
            'username': self.username,
            'website_url': self.website_url,
            'notes': self.notes,
            'category': self.category,
            'is_favorite': self.is_favorite,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'last_accessed': self.last_accessed.isoformat() if self.last_accessed else None,
            'password_strength': self.password_strength,
            'expiry_date': self.expiry_date.isoformat() if self.expiry_date else None
        }
        if include_password:
            data['password'] = self.decrypt_password()
        return data

class AuditLog(db.Model):
    """Audit log model for security tracking."""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    resource_type = db.Column(db.String(50), nullable=True)
    resource_id = db.Column(db.Integer, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'details': self.details,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }

# ============================================
# Marshmallow Schemas
# ============================================
class UserRegistrationSchema(Schema):
    """Schema for user registration."""
    email = fields.Email(required=True)
    password = fields.String(required=True, validate=validate.Length(min=8, max=128))
    master_password = fields.String(required=True, validate=validate.Length(min=8, max=128))

class UserLoginSchema(Schema):
    """Schema for user login."""
    email = fields.Email(required=True)
    password = fields.String(required=True)

class PasswordEntrySchema(Schema):
    """Schema for password entries."""
    title = fields.String(required=True, validate=validate.Length(max=255))
    username = fields.String(allow_none=True)
    password = fields.String(required=True)
    website_url = fields.Url(allow_none=True)
    notes = fields.String(allow_none=True)
    category = fields.String(validate=validate.OneOf(['login', 'credit_card', 'identity', 'secure_note', 'other']))
    is_favorite = fields.Boolean()
    expiry_date = fields.DateTime(allow_none=True)

class PasswordUpdateSchema(Schema):
    """Schema for password updates."""
    title = fields.String(validate=validate.Length(max=255))
    username = fields.String(allow_none=True)
    password = fields.String()
    website_url = fields.Url(allow_none=True)
    notes = fields.String(allow_none=True)
    category = fields.String(validate=validate.OneOf(['login', 'credit_card', 'identity', 'secure_note', 'other']))
    is_favorite = fields.Boolean()
    expiry_date = fields.DateTime(allow_none=True)

class ExportImportSchema(Schema):
    """Schema for export/import operations."""
    format = fields.String(validate=validate.OneOf(['json', 'csv', 'encrypted']))
    password = fields.String(required=True)

# Initialize schemas
user_reg_schema = UserRegistrationSchema()
user_login_schema = UserLoginSchema()
password_entry_schema = PasswordEntrySchema()
password_update_schema = PasswordUpdateSchema()

# ============================================
# Utility Functions
# ============================================
def generate_strong_password(length=16, use_uppercase=True, use_numbers=True, use_symbols=True):
    """Generate a cryptographically secure password."""
    import string
    import secrets
    
    alphabet = string.ascii_lowercase
    if use_uppercase:
        alphabet += string.ascii_uppercase
    if use_numbers:
        alphabet += string.digits
    if use_symbols:
        alphabet += string.punctuation
    
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        # Ensure password meets complexity requirements
        has_upper = use_uppercase and any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = use_numbers and any(c.isdigit() for c in password)
        has_symbol = use_symbols and any(c in string.punctuation for c in password)
        
        if has_lower and (not use_uppercase or has_upper) and \
           (not use_numbers or has_digit) and (not use_symbols or has_symbol):
            return password

def log_audit_action(user_id, action, resource_type=None, resource_id=None, details=None):
    """Log an audit action."""
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=request.remote_addr if request else None,
        user_agent=request.headers.get('User-Agent') if request else None,
        details=details
    )
    db.session.add(log)
    db.session.commit()

# ============================================
# Authentication Decorators
# ============================================
def require_active_session(f):
    """Decorator to require an active session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        verify_jwt_in_request()
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user or not user.is_active:
            return jsonify({'error': 'User not found or inactive'}), 401
        
        # Check session activity
        session_token = request.headers.get('X-Session-Token')
        if session_token:
            session = UserSession.query.filter_by(
                user_id=current_user_id,
                session_token=session_token,
                is_active=True
            ).first()
            
            if session:
                # Check for timeout (30 minutes of inactivity)
                inactivity_period = datetime.now(timezone.utc) - session.last_activity
                if inactivity_period > timedelta(minutes=30):
                    session.is_active = False
                    db.session.commit()
                    return jsonify({'error': 'Session expired due to inactivity'}), 401
                
                session.update_activity()
        
        g.current_user = user
        return f(*args, **kwargs)
    return decorated_function

# ============================================
# API Routes
# ============================================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now(timezone.utc).isoformat()})

@app.route('/api/v1/auth/register', methods=['POST'])
def register():
    """Register a new user."""
    try:
        data = user_reg_schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'error': 'Validation error', 'messages': err.messages}), 400
    
    # Check if user already exists
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 409
    
    try:
        user = User(email=data['email'])
        user.set_password(data['password'])
        user.set_master_password(data['master_password'])
        
        db.session.add(user)
        db.session.commit()
        
        log_audit_action(user.id, 'USER_REGISTERED', 'user', user.id)
        
        # Create initial session
        session = UserSession(
            user_id=user.id,
            session_token=secrets.token_urlsafe(32),
            device_info=request.headers.get('User-Agent'),
            ip_address=request.remote_addr,
            expires_at=datetime.now(timezone.utc) + timedelta(days=7)
        )
        db.session.add(session)
        db.session.commit()
        
        # Generate tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_access_token(identity=user.id, additional_claims={'type': 'refresh'})
        
        logger.info(f"User registered: {user.email}")
        
        return jsonify({
            'message': 'Registration successful',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        db.session.rollback()
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    """Authenticate user and return tokens."""
    try:
        data = user_login_schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'error': 'Validation error', 'messages': err.messages}), 400
    
    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not user.check_password(data['password']):
        log_audit_action(None, 'LOGIN_FAILED', 'user', None, f"Failed login attempt for {data['email']}")
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not user.is_active:
        return jsonify({'error': 'Account is deactivated'}), 403
    
    # Create session
    session = UserSession(
        user_id=user.id,
        session_token=secrets.token_urlsafe(32),
        device_info=request.headers.get('User-Agent'),
        ip_address=request.remote_addr,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7)
    )
    db.session.add(session)
    
    # Update last login
    user.last_login = datetime.now(timezone.utc)
    db.session.commit()
    
    log_audit_action(user.id, 'LOGIN_SUCCESS', 'user', user.id)
    
    # Generate tokens
    access_token = create_access_token(identity=user.id)
    refresh_token = create_access_token(identity=user.id, additional_claims={'type': 'refresh'})
    
    logger.info(f"User logged in: {user.email}")
    
    return jsonify({
        'message': 'Login successful',
        'access_token': access_token,
        'refresh_token': refresh_token,
        'session_token': session.session_token,
        'user': user.to_dict()
    })

@app.route('/api/v1/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    """Log out user and invalidate session."""
    current_user_id = get_jwt_identity()
    session_token = request.headers.get('X-Session-Token')
    
    if session_token:
        session = UserSession.query.filter_by(
            user_id=current_user_id,
            session_token=session_token
        ).first()
        if session:
            session.is_active = False
            db.session.commit()
    
    log_audit_action(current_user_id, 'LOGOUT', 'user', current_user_id)
    
    return jsonify({'message': 'Logged out successfully'})

@app.route('/api/v1/auth/refresh', methods=['POST'])
def refresh_token():
    """Refresh access token using refresh token."""
    from flask_jwt_extended import decode_token
    from jwt import ExpiredSignatureError, InvalidTokenError
    
    try:
        refresh_token_value = request.headers.get('Authorization').split()[1]
        decoded = decode_token(refresh_token_value)
        
        if decoded.get('type') != 'refresh':
            return jsonify({'error': 'Invalid token type'}), 401
        
        user_id = decoded['sub']
        user = User.query.get(user_id)
        
        if not user or not user.is_active:
            return jsonify({'error': 'User not found or inactive'}), 401
        
        new_access_token = create_access_token(identity=user_id)
        
        return jsonify({
            'access_token': new_access_token
        })
        
    except ExpiredSignatureError:
        return jsonify({'error': 'Refresh token expired'}), 401
    except (InvalidTokenError, Exception) as e:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/api/v1/auth/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """Get current user profile."""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({'user': user.to_dict()})

@app.route('/api/v1/auth/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    """Update user profile."""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    
    if 'master_password' in data:
        if 'current_master_password' not in data:
            return jsonify({'error': 'Current master password required'}), 400
        if not user.check_master_password(data['current_master_password']):
            return jsonify({'error': 'Invalid master password'}), 401
        user.set_master_password(data['master_password'])
    
    if 'two_factor_enabled' in data:
        user.two_factor_enabled = data['two_factor_enabled']
    
    db.session.commit()
    log_audit_action(current_user_id, 'PROFILE_UPDATED', 'user', current_user_id)
    
    return jsonify({'message': 'Profile updated', 'user': user.to_dict()})

# ============================================
# Password Entry Routes
# ============================================
@app.route('/api/v1/passwords', methods=['GET'])
@jwt_required()
def list_passwords():
    """List all password entries for current user."""
    current_user_id = get_jwt_identity()
    
    # Query parameters
    category = request.args.get('category')
    search = request.args.get('search')
    favorites_only = request.args.get('favorites', 'false').lower() == 'true'
    
    query = PasswordEntry.query.filter_by(user_id=current_user_id)
    
    if category:
        query = query.filter_by(category=category)
    
    if favorites_only:
        query = query.filter_by(is_favorite=True)
    
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (PasswordEntry.title.ilike(search_term)) |
            (PasswordEntry.username.ilike(search_term)) |
            (PasswordEntry.website_url.ilike(search_term))
        )
    
    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    pagination = query.order_by(PasswordEntry.updated_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'passwords': [entry.to_dict() for entry in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': pagination.page
    })

@app.route('/api/v1/passwords/<int:entry_id>', methods=['GET'])
@jwt_required()
def get_password(entry_id):
    """Get a specific password entry with decrypted password."""
    current_user_id = get_jwt_identity()
    
    entry = PasswordEntry.query.filter_by(
        id=entry_id,
        user_id=current_user_id
    ).first()
    
    if not entry:
        return jsonify({'error': 'Entry not found'}), 404
    
    # Update last accessed
    entry.last_accessed = datetime.now(timezone.utc)
    db.session.commit()
    
    log_audit_action(current_user_id, 'PASSWORD_ACCESSED', 'password_entry', entry_id)
    
    return jsonify({'entry': entry.to_dict(include_password=True)})

@app.route('/api/v1/passwords', methods=['POST'])
@jwt_required()
def create_password():
    """Create a new password entry."""
    current_user_id = get_jwt_identity()
    
    try:
        data = password_entry_schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'error': 'Validation error', 'messages': err.messages}), 400
    
    entry = PasswordEntry(
        user_id=current_user_id,
        title=data['title'],
        username=data.get('username'),
        website_url=data.get('website_url'),
        notes=data.get('notes'),
        category=data.get('category', 'other'),
        is_favorite=data.get('is_favorite', False),
        expiry_date=data.get('expiry_date')
    )
    
    entry.encrypt_password(data['password'])
    
    # Calculate password strength (simple implementation)
    password = data['password']
    strength = 0
    if len(password) >= 8:
        strength += 1
    if len(password) >= 12:
        strength += 1
    if any(c.isupper() for c in password):
        strength += 1
    if any(c.islower() for c in password):
        strength += 1
    if any(c.isdigit() for c in password):
        strength += 1
    if any(c in string.punctuation for c in password):
        strength += 1
    entry.password_strength = min(strength * 20, 100)
    
    db.session.add(entry)
    db.session.commit()
    
    log_audit_action(current_user_id, 'PASSWORD_CREATED', 'password_entry', entry.id)
    
    return jsonify({
        'message': 'Password entry created',
        'entry': entry.to_dict(include_password=True)
    }), 201

@app.route('/api/v1/passwords/<int:entry_id>', methods=['PUT'])
@jwt_required()
def update_password(entry_id):
    """Update a password entry."""
    current_user_id = get_jwt_identity()
    
    entry = PasswordEntry.query.filter_by(
        id=entry_id,
        user_id=current_user_id
    ).first()
    
    if not entry:
        return jsonify({'error': 'Entry not found'}), 404
    
    try:
        data = password_update_schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'error': 'Validation error', 'messages': err.messages}), 400
    
    # Update fields
    if 'title' in data:
        entry.title = data['title']
    if 'username' in data:
        entry.username = data['username']
    if 'website_url' in data:
        entry.website_url = data['website_url']
    if 'notes' in data:
        entry.notes = data['notes']
    if 'category' in data:
        entry.category = data['category']
    if 'is_favorite' in data:
        entry.is_favorite = data['is_favorite']
    if 'expiry_date' in data:
        entry.expiry_date = data['expiry_date']
    if 'password' in data:
        entry.encrypt_password(data['password'])
        # Recalculate strength
        password = data['password']
        strength = 0
        if len(password) >= 8:
            strength += 1
        if len(password) >= 12:
            strength += 1
        if any(c.isupper() for c in password):
            strength += 1
        if any(c.islower() for c in password):
            strength += 1
        if any(c.isdigit() for c in password):
            strength += 1
        if any(c in string.punctuation for c in password):
            strength += 1
        entry.password_strength = min(strength * 20, 100)
    
    db.session.commit()
    log_audit_action(current_user_id, 'PASSWORD_UPDATED', 'password_entry', entry_id)
    
    return jsonify({
        'message': 'Password entry updated',
        'entry': entry.to_dict(include_password=True)
    })

@app.route('/api/v1/passwords/<int:entry_id>', methods=['DELETE'])
@jwt_required()
def delete_password(entry_id):
    """Delete a password entry."""
    current_user_id = get_jwt_identity()
    
    entry = PasswordEntry.query.filter_by(
        id=entry_id,
        user_id=current_user_id
    ).first()
    
    if not entry:
        return jsonify({'error': 'Entry not found'}), 404
    
    db.session.delete(entry)
    db.session.commit()
    
    log_audit_action(current_user_id, 'PASSWORD_DELETED', 'password_entry', entry_id)
    
    return jsonify({'message': 'Password entry deleted'})

@app.route('/api/v1/passwords/<int:entry_id>/favorite', methods=['POST'])
@jwt_required()
def toggle_favorite(entry_id):
    """Toggle favorite status of a password entry."""
    current_user_id = get_jwt_identity()
    
    entry = PasswordEntry.query.filter_by(
        id=entry_id,
        user_id=current_user_id
    ).first()
    
    if not entry:
        return jsonify({'error': 'Entry not found'}), 404
    
    entry.is_favorite = not entry.is_favorite
    db.session.commit()
    
    action = 'FAVORITE_ADDED' if entry.is_favorite else 'FAVORITE_REMOVED'
    log_audit_action(current_user_id, action, 'password_entry', entry_id)
    
    return jsonify({
        'message': 'Favorite status toggled',
        'is_favorite': entry.is_favorite
    })

# ============================================
# Password Generator Route
# ============================================
@app.route('/api/v1/generate-password', methods=['GET'])
@jwt_required()
def generate_password():
    """Generate a secure random password."""
    current_user_id = get_jwt_identity()
    
    length = request.args.get('length', 16, type=int)
    use_uppercase = request.args.get('uppercase', 'true').lower() == 'true'
    use_numbers = request.args.get('numbers', 'true').lower() == 'true'
    use_symbols = request.args.get('symbols', 'true').lower() == 'true'
    
    # Limit length
    length = min(max(length, 8), 64)
    
    password = generate_strong_password(
        length=length,
        use_uppercase=use_uppercase,
        use_numbers=use_numbers,
        use_symbols=use_symbols
    )
    
    log_audit_action(current_user_id, 'PASSWORD_GENERATED')
    
    return jsonify({
        'password': password,
        'length': len(password)
    })

# ============================================
# Export/Import Routes
# ============================================
@app.route('/api/v1/export', methods=['GET'])
@jwt_required()
def export_passwords():
    """Export all passwords in encrypted format."""
    current_user_id = get_jwt_identity()
    
    passwords = PasswordEntry.query.filter_by(user_id=current_user_id).all()
    
    export_data = {
        'version': '1.0',
        'export_date': datetime.now(timezone.utc).isoformat(),
        'user_email': User.query.get(current_user_id).email,
        'entries': [entry.to_dict(include_password=True) for entry in passwords]
    }
    
    log_audit_action(current_user_id, 'EXPORT_REQUESTED')
    
    return jsonify(export_data)

@app.route('/api/v1/import', methods=['POST'])
@jwt_required()
def import_passwords():
    """Import passwords from encrypted format."""
    current_user_id = get_jwt_identity()
    
    data = request.get_json()
    
    if 'entries' not in data:
        return jsonify({'error': 'Invalid import data'}), 400
    
    imported_count = 0
    errors = []
    
    for entry_data in data['entries']:
        try:
            entry = PasswordEntry(
                user_id=current_user_id,
                title=entry_data.get('title', 'Imported'),
                username=entry_data.get('username'),
                encrypted_password=entry_data.get('encrypted_password', ''),
                website_url=entry_data.get('website_url'),
                notes=entry_data.get('notes'),
                category=entry_data.get('category', 'other'),
                is_favorite=entry_data.get('is_favorite', False)
            )
            db.session.add(entry)
            imported_count += 1
        except Exception as e:
            errors.append(str(e))
    
    db.session.commit()
    
    log_audit_action(current_user_id, 'IMPORT_COMPLETED', details=f"Imported {imported_count} entries")
    
    return jsonify({
        'message': 'Import completed',
        'imported_count': imported_count,
        'errors': errors
    })

# ============================================
# Audit Log Routes
# ============================================
@app.route('/api/v1/audit-logs', methods=['GET'])
@jwt_required()
def get_audit_logs():
    """Get audit logs for current user."""
    current_user_id = get_jwt_identity()
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    pagination = AuditLog.query.filter_by(user_id=current_user_id).order_by(
        AuditLog.timestamp.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'logs': [log.to_dict() for log in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': pagination.page
    })

# ============================================
# Statistics Route
# ============================================
@app.route('/api/v1/stats', methods=['GET'])
@jwt_required()
def get_stats():
    """Get password statistics for current user."""
    current_user_id = get_jwt_identity()
    
    total_passwords = PasswordEntry.query.filter_by(user_id=current_user_id).count()
    favorite_count = PasswordEntry.query.filter_by(user_id=current_user_id, is_favorite=True).count()
    
    # Category breakdown
    categories = db.session.query(
        PasswordEntry.category,
        db.func.count(PasswordEntry.id)
    ).filter_by(user_id=current_user_id).group_by(PasswordEntry.category).all()
    
    category_breakdown = {cat: count for cat, count in categories}
    
    # Password strength distribution
    strength_distribution = {
        'weak': PasswordEntry.query.filter(
            PasswordEntry.user_id == current_user_id,
            PasswordEntry.password_strength <= 40
        ).count(),
        'medium': PasswordEntry.query.filter(
            PasswordEntry.user_id == current_user_id,
            PasswordEntry.password_strength > 40,
            PasswordEntry.password_strength <= 70
        ).count(),
        'strong': PasswordEntry.query.filter(
            PasswordEntry.user_id == current_user_id,
            PasswordEntry.password_strength > 70
        ).count()
    }
    
    return jsonify({
        'total_passwords': total_passwords,
        'favorite_count': favorite_count,
        'category_breakdown': category_breakdown,
        'strength_distribution': strength_distribution
    })

# ============================================
# Session Management
# ============================================
@app.route('/api/v1/sessions', methods=['GET'])
@jwt_required()
def get_sessions():
    """Get all active sessions for current user."""
    current_user_id = get_jwt_identity()
    
    sessions = UserSession.query.filter_by(
        user_id=current_user_id,
        is_active=True
    ).order_by(desc(UserSession.last_activity)).all()
    
    return jsonify({
        'sessions': [session.to_dict() for session in sessions]
    })

@app.route('/api/v1/sessions/<int:session_id>', methods=['DELETE'])
@jwt_required()
def revoke_session(session_id):
    """Revoke a specific session."""
    current_user_id = get_jwt_identity()
    
    session = UserSession.query.filter_by(
        id=session_id,
        user_id=current_user_id
    ).first()
    
    if not session:
        return jsonify({'error': 'Session not found'}), 404
    
    session.is_active = False
    db.session.commit()
    
    log_audit_action(current_user_id, 'SESSION_REVOKED', 'session', session_id)
    
    return jsonify({'message': 'Session revoked'})

# ============================================
# Error Handlers
# ============================================
@app.errorhandler(400)
def bad_request(error):
    """Handle bad request errors."""
    return jsonify({'error': 'Bad request'}), 400

@app.errorhandler(401)
def unauthorized(error):
    """Handle unauthorized errors."""
    return jsonify({'error': 'Unauthorized'}), 401

@app.errorhandler(403)
def forbidden(error):
    """Handle forbidden errors."""
    return jsonify({'error': 'Forbidden'}), 403

@app.errorhandler(404)
def not_found(error):
    """Handle not found errors."""
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors."""
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

# ============================================
# Database Initialization
# ============================================
def init_db():
    """Initialize the database."""
    with app.app_context():
        db.create_all()
        logger.info("Database initialized successfully")

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)

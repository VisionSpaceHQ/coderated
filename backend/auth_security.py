# auth_security.py - Advanced Authentication & Authorization
import bcrypt
import jwt
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, g
import redis
import json
import secrets
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import re
from email_validator import validate_email, EmailNotValidError

class AuthenticationManager:
    def __init__(self, redis_client=None):
        self.redis_client = redis_client or redis.Redis(decode_responses=True)
        self.secret_key = os.getenv('SECRET_KEY', 'your-secret-key')
        self.jwt_algorithm = 'HS256'
        self.access_token_expire = timedelta(hours=1)
        self.refresh_token_expire = timedelta(days=30)
        
        # Password requirements
        self.min_password_length = 12
        self.require_uppercase = True
        self.require_lowercase = True
        self.require_numbers = True
        self.require_special = True
        
        # Account lockout settings
        self.max_login_attempts = 5
        self.lockout_duration = 1800  # 30 minutes

    def hash_password(self, password: str) -> str:
        """Hash password with bcrypt and additional security"""
        # Add pepper (server-side secret)
        pepper = os.getenv('PASSWORD_PEPPER', 'default-pepper')
        peppered_password = password + pepper
        
        # Generate salt and hash
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(peppered_password.encode('utf-8'), salt)
        
        return hashed.decode('utf-8')

    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        pepper = os.getenv('PASSWORD_PEPPER', 'default-pepper')
        peppered_password = password + pepper
        
        try:
            return bcrypt.checkpw(peppered_password.encode('utf-8'), hashed.encode('utf-8'))
        except ValueError:
            return False

    def validate_password_strength(self, password: str) -> tuple[bool, list]:
        """Validate password meets security requirements"""
        errors = []
        
        if len(password) < self.min_password_length:
            errors.append(f"Password must be at least {self.min_password_length} characters")
        
        if self.require_uppercase and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if self.require_lowercase and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if self.require_numbers and not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        
        if self.require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        
        # Check against common passwords
        common_passwords = [
            'password', '123456789', 'qwerty', 'abc123', 'password123',
            'admin', 'root', 'user', 'guest', 'test'
        ]
        
        if password.lower() in common_passwords:
            errors.append("Password is too common")
        
        # Check for repeated characters
        if re.search(r'(.)\1{3,}', password):
            errors.append("Password cannot contain more than 3 repeated characters")
        
        return len(errors) == 0, errors

    def validate_email_format(self, email: str) -> tuple[bool, str]:
        """Validate email format and domain"""
        try:
            # Validate email format
            valid_email = validate_email(email)
            normalized_email = valid_email.email
            
            # Check against disposable email domains
            disposable_domains = [
                '10minutemail.com', 'guerrillamail.com', 'mailinator.com',
                'tempmail.org', 'throwaway.email', 'fakeinbox.com'
            ]
            
            domain = normalized_email.split('@')[1].lower()
            if domain in disposable_domains:
                return False, "Disposable email addresses are not allowed"
            
            return True, normalized_email
            
        except EmailNotValidError:
            return False, "Invalid email format"

    def generate_tokens(self, user_id: str, email: str, tier: str) -> dict:
        """Generate access and refresh tokens"""
        now = datetime.utcnow()
        
        # Access token (short-lived)
        access_payload = {
            'user_id': user_id,
            'email': email,
            'tier': tier,
            'type': 'access',
            'iat': now,
            'exp': now + self.access_token_expire,
            'jti': secrets.token_hex(16)  # JWT ID for revocation
        }
        
        # Refresh token (long-lived)
        refresh_payload = {
            'user_id': user_id,
            'type': 'refresh',
            'iat': now,
            'exp': now + self.refresh_token_expire,
            'jti': secrets.token_hex(16)
        }
        
        access_token = jwt.encode(access_payload, self.secret_key, algorithm=self.jwt_algorithm)
        refresh_token = jwt.encode(refresh_payload, self.secret_key, algorithm=self.jwt_algorithm)
        
        # Store refresh token in Redis
        self.redis_client.setex(
            f"refresh_token:{user_id}:{refresh_payload['jti']}",
            int(self.refresh_token_expire.total_seconds()),
            refresh_token
        )
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': int(self.access_token_expire.total_seconds())
        }

    def verify_token(self, token: str, token_type: str = 'access') -> dict:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.jwt_algorithm])
            
            if payload.get('type') != token_type:
                return None
            
            # Check if token is revoked
            jti = payload.get('jti')
            if self.redis_client.exists(f"revoked_token:{jti}"):
                return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def revoke_token(self, token: str):
        """Revoke a token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.jwt_algorithm], options={"verify_exp": False})
            jti = payload.get('jti')
            exp = payload.get('exp')
            
            if jti and exp:
                # Store revoked token until it would naturally expire
                ttl = max(0, exp - int(datetime.utcnow().timestamp()))
                self.redis_client.setex(f"revoked_token:{jti}", ttl, "revoked")
                
        except jwt.InvalidTokenError:
            pass

    def refresh_access_token(self, refresh_token: str) -> dict:
        """Refresh access token using refresh token"""
        payload = self.verify_token(refresh_token, 'refresh')
        if not payload:
            return None
        
        user_id = payload['user_id']
        jti = payload['jti']
        
        # Check if refresh token exists in Redis
        if not self.redis_client.exists(f"refresh_token:{user_id}:{jti}"):
            return None
        
        # Get user info (you'll need to implement this based on your user model)
        user_info = self.get_user_info(user_id)
        if not user_info:
            return None
        
        # Generate new tokens
        return self.generate_tokens(user_id, user_info['email'], user_info['tier'])

    def check_login_attempts(self, identifier: str) -> bool:
        """Check if account is locked due to failed login attempts"""
        key = f"login_attempts:{identifier}"
        attempts = self.redis_client.get(key)
        
        if attempts and int(attempts) >= self.max_login_attempts:
            return False
        
        return True

    def record_login_attempt(self, identifier: str, success: bool):
        """Record login attempt"""
        key = f"login_attempts:{identifier}"
        
        if success:
            # Clear failed attempts on successful login
            self.redis_client.delete(key)
        else:
            # Increment failed attempts
            pipe = self.redis_client.pipeline()
            pipe.incr(key)
            pipe.expire(key, self.lockout_duration)
            pipe.execute()

    def setup_2fa(self, user_id: str, issuer_name: str = "CodeRated") -> dict:
        """Setup 2FA for user"""
        # Generate secret
        secret = pyotp.random_base32()
        
        # Store secret (encrypted) in Redis temporarily
        encrypted_secret = self.encrypt_data(secret)
        self.redis_client.setex(f"2fa_setup:{user_id}", 300, encrypted_secret)  # 5 minutes
        
        # Generate QR code
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user_id,
            issuer_name=issuer_name
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        return {
            'secret': secret,
            'qr_code': f"data:image/png;base64,{qr_code_base64}",
            'manual_entry_key': secret
        }

    def verify_2fa(self, user_id: str, token: str, secret: str = None) -> bool:
        """Verify 2FA token"""
        if not secret:
            # Get secret from user's stored 2FA settings
            secret = self.get_user_2fa_secret(user_id)
        
        if not secret:
            return False
        
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)  # Allow 1 window of tolerance

    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        from cryptography.fernet import Fernet
        key = os.getenv('ENCRYPTION_KEY', Fernet.generate_key())
        cipher_suite = Fernet(key)
        return cipher_suite.encrypt(data.encode()).decode()

    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        from cryptography.fernet import Fernet
        key = os.getenv('ENCRYPTION_KEY')
        cipher_suite = Fernet(key)
        return cipher_suite.decrypt(encrypted_data.encode()).decode()

    def generate_secure_session_id(self) -> str:
        """Generate cryptographically secure session ID"""
        return secrets.token_urlsafe(32)

    def get_user_info(self, user_id: str) -> dict:
        """Get user info - implement based on your user model"""
        # This is a placeholder - implement based on your database
        pass

    def get_user_2fa_secret(self, user_id: str) -> str:
        """Get user's 2FA secret - implement based on your user model"""
        # This is a placeholder - implement based on your database
        pass

# Authentication decorators
def require_auth(require_2fa: bool = False):
    """Decorator to require authentication"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Authentication required'}), 401
            
            token = auth_header.split(' ')[1]
            payload = auth_manager.verify_token(token)
            
            if not payload:
                return jsonify({'error': 'Invalid or expired token'}), 401
            
            # Check 2FA if required
            if require_2fa:
                user_2fa_enabled = check_user_2fa_enabled(payload['user_id'])
                if user_2fa_enabled and not payload.get('2fa_verified'):
                    return jsonify({'error': '2FA verification required'}), 403
            
            # Store user info in request context
            g.current_user = payload
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_tier(required_tier: str):
    """Decorator to require specific user tier"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'current_user'):
                return jsonify({'error': 'Authentication required'}), 401
            
            user_tier = g.current_user.get('tier')
            
            # Define tier hierarchy
            tier_levels = {
                'observer': 1,
                'analyst': 2,
                'pro': 3,
                'enterprise': 4
            }
            
            if tier_levels.get(user_tier, 0) < tier_levels.get(required_tier, 999):
                return jsonify({'error': f'Tier {required_tier} or higher required'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def check_user_2fa_enabled(user_id: str) -> bool:
    """Check if user has 2FA enabled"""
    # Implement based on your user model
    return False

# Initialize authentication manager
auth_manager = AuthenticationManager()

# Add these functions at the END of your auth_security.py file

# Initialize authentication manager
auth_manager = AuthenticationManager()

# Standalone functions that your API server expects
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Standalone password verification function"""
    return auth_manager.verify_password(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Standalone password hashing function"""
    return auth_manager.hash_password(password)

def create_access_token(data: dict, expires_delta=None):
    """Create access token - simplified version"""
    import jwt
    from datetime import datetime, timedelta
    
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=1)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, auth_manager.secret_key, algorithm=auth_manager.jwt_algorithm)
    return encoded_jwt

def get_current_user(token: str):
    """Get current user from token"""
    payload = auth_manager.verify_token(token)
    if not payload:
        return None
    return payload

def get_admin_user(user_data: dict):
    """Check if user is admin"""
    if not user_data:
        return None
    
    user_tier = user_data.get('tier', 'observer')
    tier_levels = {
        'observer': 1,
        'analyst': 2,
        'pro': 3,
        'business': 4,
        'enterprise': 5,
        'admin': 6
    }
    
    if tier_levels.get(user_tier, 0) >= tier_levels.get('business', 4):
        return user_data
    return None
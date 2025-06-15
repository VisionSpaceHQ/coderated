# security.py - Advanced API Security System
import hashlib
import hmac
import json
import time
import redis
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import re
import ipaddress
from collections import defaultdict
import bleach
from cryptography.fernet import Fernet
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
security_logger = logging.getLogger('security')

class SecurityManager:
    def __init__(self, redis_client=None):
        self.redis_client = redis_client or redis.Redis(decode_responses=True)
        self.encryption_key = os.getenv('ENCRYPTION_KEY', Fernet.generate_key())
        self.cipher_suite = Fernet(self.encryption_key)
        
        # Rate limiting storage
        self.rate_limits = defaultdict(list)
        
        # Blocked IPs and suspicious activity
        self.blocked_ips = set()
        self.suspicious_patterns = [
            r'<script[^>]*>.*?</script>',  # XSS
            r'union.*select',              # SQL injection
            r'drop\s+table',              # SQL injection
            r'exec\s*\(',                 # Code injection
            r'eval\s*\(',                 # Code injection
            r'\.\./',                     # Path traversal
            r'<iframe',                   # XSS iframe
            r'javascript:',               # XSS javascript
            r'data:text/html',            # Data URI XSS
        ]
        
    def generate_api_key(self, user_id: str, tier: str) -> str:
        """Generate secure API key with embedded metadata"""
        timestamp = int(time.time())
        payload = {
            'user_id': user_id,
            'tier': tier,
            'created': timestamp,
            'version': '1.0'
        }
        
        # Create signed token
        token = jwt.encode(
            payload,
            os.getenv('SECRET_KEY'),
            algorithm='HS256'
        )
        
        # Add prefix for identification
        api_key = f"cr_{tier}_{token}"
        
        # Store in Redis with expiration
        self.redis_client.setex(
            f"api_key:{api_key}",
            86400 * 30,  # 30 days
            json.dumps(payload)
        )
        
        return api_key

    def validate_api_key(self, api_key: str) -> dict:
        """Validate API key and return user info"""
        if not api_key or not api_key.startswith('cr_'):
            return None
            
        try:
            # Check Redis cache first
            cached = self.redis_client.get(f"api_key:{api_key}")
            if cached:
                return json.loads(cached)
                
            # Extract and verify JWT
            token_part = api_key.split('_', 2)[2]
            payload = jwt.decode(
                token_part,
                os.getenv('SECRET_KEY'),
                algorithms=['HS256']
            )
            
            return payload
            
        except (jwt.InvalidTokenError, IndexError, KeyError):
            security_logger.warning(f"Invalid API key attempt: {api_key[:20]}...")
            return None

    def rate_limit_check(self, identifier: str, max_requests: int = 100, window: int = 3600) -> bool:
        """Advanced rate limiting with sliding window"""
        current_time = time.time()
        window_start = current_time - window
        
        # Get current requests in window
        pipe = self.redis_client.pipeline()
        key = f"rate_limit:{identifier}"
        
        # Remove old entries and add current request
        pipe.zremrangebyscore(key, 0, window_start)
        pipe.zadd(key, {str(current_time): current_time})
        pipe.zcard(key)
        pipe.expire(key, window)
        
        results = pipe.execute()
        current_requests = results[2]
        
        if current_requests > max_requests:
            self.log_security_event(
                'RATE_LIMIT_EXCEEDED',
                {'identifier': identifier, 'requests': current_requests}
            )
            return False
            
        return True

    def detect_malicious_input(self, data: str) -> bool:
        """Detect malicious patterns in input"""
        data_lower = data.lower()
        
        for pattern in self.suspicious_patterns:
            if re.search(pattern, data_lower, re.IGNORECASE):
                self.log_security_event(
                    'MALICIOUS_INPUT_DETECTED',
                    {'pattern': pattern, 'data': data[:100]}
                )
                return True
                
        return False

    def sanitize_input(self, data: str) -> str:
        """Sanitize user input"""
        # Remove dangerous HTML tags and scripts
        cleaned = bleach.clean(
            data,
            tags=['p', 'br', 'strong', 'em'],
            attributes={},
            strip=True
        )
        
        # Additional cleaning
        cleaned = re.sub(r'[<>"\']', '', cleaned)
        
        return cleaned.strip()

    def validate_ip_address(self, ip: str) -> bool:
        """Validate and check IP address against blacklists"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if IP is in blocked list
            if ip in self.blocked_ips:
                return False
                
            # Check against known malicious IP ranges (you can expand this)
            blocked_ranges = [
                '10.0.0.0/8',    # Private networks (if not expected)
                '172.16.0.0/12',
                '192.168.0.0/16'
            ]
            
            for blocked_range in blocked_ranges:
                if ip_obj in ipaddress.ip_network(blocked_range):
                    # Allow if it's expected (e.g., internal requests)
                    if not os.getenv('ALLOW_PRIVATE_IPS', 'false').lower() == 'true':
                        return False
                        
            return True
            
        except ValueError:
            return False

    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        return self.cipher_suite.encrypt(data.encode()).decode()

    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        return self.cipher_suite.decrypt(encrypted_data.encode()).decode()

    def log_security_event(self, event_type: str, details: dict):
        """Log security events for monitoring"""
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'type': event_type,
            'details': details,
            'ip': request.remote_addr if request else 'unknown',
            'user_agent': request.headers.get('User-Agent', 'unknown') if request else 'unknown'
        }
        
        security_logger.warning(f"SECURITY_EVENT: {json.dumps(event)}")
        
        # Store in Redis for analysis
        self.redis_client.lpush(
            'security_events',
            json.dumps(event)
        )
        
        # Keep only last 1000 events
        self.redis_client.ltrim('security_events', 0, 999)

    def check_request_signature(self, signature: str, payload: str, secret: str) -> bool:
        """Verify request signature for webhooks"""
        expected_signature = hmac.new(
            secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, expected_signature)

# Security decorators
def require_api_key(tier_required: str = None):
    """Decorator to require valid API key"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get API key from header
            api_key = request.headers.get('X-API-Key') or request.headers.get('Authorization', '').replace('Bearer ', '')
            
            if not api_key:
                return jsonify({'error': 'API key required'}), 401
                
            # Validate API key
            user_info = security_manager.validate_api_key(api_key)
            if not user_info:
                return jsonify({'error': 'Invalid API key'}), 401
                
            # Check tier requirement
            if tier_required and user_info.get('tier') != tier_required:
                return jsonify({'error': f'Tier {tier_required} required'}), 403
                
            # Store user info in request context
            g.current_user = user_info
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def rate_limit(max_requests: int = 100, window: int = 3600):
    """Decorator for rate limiting"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Use API key or IP as identifier
            identifier = getattr(g, 'current_user', {}).get('user_id') or request.remote_addr
            
            if not security_manager.rate_limit_check(identifier, max_requests, window):
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'retry_after': window
                }), 429
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_input(*fields):
    """Decorator to validate and sanitize input fields"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            request_data = request.get_json() or {}
            
            for field in fields:
                if field in request_data:
                    value = str(request_data[field])
                    
                    # Check for malicious patterns
                    if security_manager.detect_malicious_input(value):
                        security_manager.log_security_event(
                            'MALICIOUS_INPUT_BLOCKED',
                            {'field': field, 'value': value[:100]}
                        )
                        return jsonify({'error': 'Invalid input detected'}), 400
                        
                    # Sanitize input
                    request_data[field] = security_manager.sanitize_input(value)
            
            # Replace request data
            request._cached_json = request_data
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def security_headers():
    """Decorator to add security headers"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            response = f(*args, **kwargs)
            
            # Add security headers
            if hasattr(response, 'headers'):
                response.headers['X-Content-Type-Options'] = 'nosniff'
                response.headers['X-Frame-Options'] = 'DENY'
                response.headers['X-XSS-Protection'] = '1; mode=block'
                response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
                response.headers['Content-Security-Policy'] = "default-src 'self'"
                response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            
            return response
        return decorated_function
    return decorator

def ip_whitelist(allowed_ips: list):
    """Decorator to restrict access to specific IPs"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr
            
            if client_ip not in allowed_ips:
                security_manager.log_security_event(
                    'IP_ACCESS_DENIED',
                    {'ip': client_ip, 'allowed_ips': allowed_ips}
                )
                return jsonify({'error': 'Access denied'}), 403
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Initialize security manager
security_manager = SecurityManager()

# Middleware function to add to Flask app
def init_security_middleware(app):
    """Initialize security middleware for Flask app"""
    
    @app.before_request
    def security_check():
        # Skip security checks for health endpoint
        if request.endpoint == 'health':
            return
            
        # Validate IP address
        client_ip = request.remote_addr
        if not security_manager.validate_ip_address(client_ip):
            security_manager.log_security_event(
                'BLOCKED_IP_ACCESS',
                {'ip': client_ip}
            )
            return jsonify({'error': 'Access denied'}), 403
            
        # Check for suspicious user agents
        user_agent = request.headers.get('User-Agent', '')
        suspicious_agents = ['sqlmap', 'nikto', 'nmap', 'masscan']
        
        if any(agent in user_agent.lower() for agent in suspicious_agents):
            security_manager.log_security_event(
                'SUSPICIOUS_USER_AGENT',
                {'user_agent': user_agent, 'ip': client_ip}
            )
            return jsonify({'error': 'Access denied'}), 403
            
        # Basic DDoS protection
        if not security_manager.rate_limit_check(f"global:{client_ip}", 1000, 3600):
            return jsonify({'error': 'Too many requests'}), 429
    
    @app.after_request
    def add_security_headers(response):
        # Add security headers to all responses
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Remove server header
        response.headers.pop('Server', None)
        
        return response
    
    return app
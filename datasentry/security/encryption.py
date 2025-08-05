import base64
import hashlib
import os
from typing import Any, Dict, Optional, Union
from datetime import datetime, timedelta
import json
import structlog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from passlib.context import CryptContext
from jose import JWTError, jwt

logger = structlog.get_logger(__name__)


class EncryptionManager:
    """Manages encryption/decryption for sensitive data"""
    
    def __init__(self, master_key: Optional[bytes] = None):
        if master_key:
            self.master_key = master_key
        else:
            self.master_key = self._generate_master_key()
        
        self.fernet = Fernet(base64.urlsafe_b64encode(self.master_key[:32]))
        
        # Password hashing
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    
    def _generate_master_key(self) -> bytes:
        """Generate a master encryption key"""
        # In production, this should come from a secure key management service
        return os.urandom(32)
    
    def encrypt_data(self, data: Union[str, bytes, dict]) -> str:
        """Encrypt sensitive data"""
        try:
            if isinstance(data, dict):
                data = json.dumps(data)
            elif isinstance(data, str):
                data = data.encode('utf-8')
            
            encrypted_data = self.fernet.encrypt(data)
            return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            logger.error("Encryption failed", error=str(e))
            raise EncryptionError(f"Failed to encrypt data: {str(e)}")
    
    def decrypt_data(self, encrypted_data: str) -> bytes:
        """Decrypt sensitive data"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
            decrypted_data = self.fernet.decrypt(encrypted_bytes)
            return decrypted_data
            
        except Exception as e:
            logger.error("Decryption failed", error=str(e))
            raise DecryptionError(f"Failed to decrypt data: {str(e)}")
    
    def decrypt_to_string(self, encrypted_data: str) -> str:
        """Decrypt and return as string"""
        decrypted_bytes = self.decrypt_data(encrypted_data)
        return decrypted_bytes.decode('utf-8')
    
    def decrypt_to_dict(self, encrypted_data: str) -> dict:
        """Decrypt and return as dictionary"""
        decrypted_string = self.decrypt_to_string(encrypted_data)
        return json.loads(decrypted_string)
    
    def hash_password(self, password: str) -> str:
        """Hash password securely"""
        return self.pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password"""
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def generate_key_from_password(self, password: str, salt: bytes = None) -> bytes:
        """Generate encryption key from password"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode())
        return key
    
    def encrypt_with_key(self, data: str, key: bytes) -> str:
        """Encrypt data with specific key"""
        f = Fernet(base64.urlsafe_b64encode(key))
        encrypted = f.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt_with_key(self, encrypted_data: str, key: bytes) -> str:
        """Decrypt data with specific key"""
        f = Fernet(base64.urlsafe_b64encode(key))
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data)
        decrypted = f.decrypt(encrypted_bytes)
        return decrypted.decode()


class PIIEncryption:
    """Specialized encryption for PII data"""
    
    def __init__(self, encryption_manager: EncryptionManager):
        self.encryption_manager = encryption_manager
    
    def encrypt_pii_detection(self, detection_data: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt PII detection results"""
        encrypted_data = detection_data.copy()
        
        # Encrypt sensitive fields
        if 'detected_entities' in encrypted_data:
            encrypted_entities = []
            for entity in encrypted_data['detected_entities']:
                encrypted_entity = entity.copy()
                if 'text' in encrypted_entity:
                    encrypted_entity['text'] = self.encryption_manager.encrypt_data(
                        encrypted_entity['text']
                    )
                if 'context' in encrypted_entity:
                    encrypted_entity['context'] = self.encryption_manager.encrypt_data(
                        encrypted_entity['context']
                    )
                encrypted_entities.append(encrypted_entity)
            encrypted_data['detected_entities'] = encrypted_entities
        
        if 'original_text' in encrypted_data:
            encrypted_data['original_text'] = self.encryption_manager.encrypt_data(
                encrypted_data['original_text']
            )
        
        return encrypted_data
    
    def decrypt_pii_detection(self, encrypted_data: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt PII detection results"""
        decrypted_data = encrypted_data.copy()
        
        # Decrypt sensitive fields
        if 'detected_entities' in decrypted_data:
            decrypted_entities = []
            for entity in decrypted_data['detected_entities']:
                decrypted_entity = entity.copy()
                if 'text' in decrypted_entity:
                    decrypted_entity['text'] = self.encryption_manager.decrypt_to_string(
                        decrypted_entity['text']
                    )
                if 'context' in decrypted_entity:
                    decrypted_entity['context'] = self.encryption_manager.decrypt_to_string(
                        decrypted_entity['context']
                    )
                decrypted_entities.append(decrypted_entity)
            decrypted_data['detected_entities'] = decrypted_entities
        
        if 'original_text' in decrypted_data:
            decrypted_data['original_text'] = self.encryption_manager.decrypt_to_string(
                decrypted_data['original_text']
            )
        
        return decrypted_data


class JWTManager:
    """JWT token management for authentication"""
    
    def __init__(self, secret_key: str, algorithm: str = "HS256"):
        self.secret_key = secret_key
        self.algorithm = algorithm
    
    def create_access_token(
        self, 
        data: Dict[str, Any], 
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(hours=1)
        
        to_encode.update({"exp": expire, "iat": datetime.utcnow()})
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except JWTError as e:
            logger.warning("JWT verification failed", error=str(e))
            return None
    
    def create_refresh_token(self, user_id: str) -> str:
        """Create refresh token"""
        data = {"sub": user_id, "type": "refresh"}
        return self.create_access_token(data, expires_delta=timedelta(days=7))
    
    def is_token_expired(self, token: str) -> bool:
        """Check if token is expired"""
        payload = self.verify_token(token)
        if not payload:
            return True
        
        exp = payload.get("exp")
        if not exp:
            return True
        
        return datetime.utcnow().timestamp() > exp


class APIKeyManager:
    """Secure API key generation and validation"""
    
    def __init__(self, encryption_manager: EncryptionManager):
        self.encryption_manager = encryption_manager
        self.api_keys = {}  # In production, use database
    
    def generate_api_key(
        self, 
        user_id: str, 
        permissions: List[str],
        expires_at: Optional[datetime] = None
    ) -> str:
        """Generate secure API key"""
        # Generate random key
        key_data = {
            "user_id": user_id,
            "permissions": permissions,
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": expires_at.isoformat() if expires_at else None
        }
        
        # Create key ID
        key_id = hashlib.sha256(
            f"{user_id}:{datetime.utcnow().timestamp()}".encode()
        ).hexdigest()[:16]
        
        # Encrypt key data
        encrypted_data = self.encryption_manager.encrypt_data(key_data)
        
        # Store in memory (use database in production)
        self.api_keys[key_id] = encrypted_data
        
        # Return API key format: keyid.encrypted_data
        return f"ds_{key_id}.{encrypted_data}"
    
    def validate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Validate API key and return user info"""
        try:
            if not api_key.startswith("ds_"):
                return None
            
            # Parse key
            key_part = api_key[3:]  # Remove "ds_" prefix
            key_id, encrypted_data = key_part.split(".", 1)
            
            # Verify key exists
            if key_id not in self.api_keys:
                return None
            
            # Decrypt key data
            key_data = self.encryption_manager.decrypt_to_dict(encrypted_data)
            
            # Check expiration
            if key_data.get("expires_at"):
                expires_at = datetime.fromisoformat(key_data["expires_at"])
                if datetime.utcnow() > expires_at:
                    return None
            
            return key_data
            
        except Exception as e:
            logger.warning("API key validation failed", error=str(e))
            return None
    
    def revoke_api_key(self, api_key: str) -> bool:
        """Revoke API key"""
        try:
            key_part = api_key[3:]  # Remove "ds_" prefix
            key_id = key_part.split(".", 1)[0]
            
            if key_id in self.api_keys:
                del self.api_keys[key_id]
                return True
            
            return False
            
        except Exception:
            return False
    
    def list_user_keys(self, user_id: str) -> List[Dict[str, Any]]:
        """List API keys for user"""
        user_keys = []
        
        for key_id, encrypted_data in self.api_keys.items():
            try:
                key_data = self.encryption_manager.decrypt_to_dict(encrypted_data)
                if key_data.get("user_id") == user_id:
                    user_keys.append({
                        "key_id": key_id,
                        "permissions": key_data.get("permissions", []),
                        "created_at": key_data.get("created_at"),
                        "expires_at": key_data.get("expires_at")
                    })
            except Exception:
                continue
        
        return user_keys


class SecureLogger:
    """Secure logging with PII redaction"""
    
    def __init__(self, encryption_manager: EncryptionManager):
        self.encryption_manager = encryption_manager
        self.logger = structlog.get_logger(__name__)
    
    def log_with_pii_redaction(
        self, 
        level: str, 
        message: str, 
        **kwargs
    ):
        """Log message with automatic PII redaction"""
        # Redact PII from kwargs
        redacted_kwargs = self._redact_pii_from_dict(kwargs)
        
        # Log based on level
        if level.lower() == "debug":
            self.logger.debug(message, **redacted_kwargs)
        elif level.lower() == "info":
            self.logger.info(message, **redacted_kwargs)
        elif level.lower() == "warning":
            self.logger.warning(message, **redacted_kwargs)
        elif level.lower() == "error":
            self.logger.error(message, **redacted_kwargs)
    
    def _redact_pii_from_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Redact PII from dictionary values"""
        redacted = {}
        
        for key, value in data.items():
            if self._is_sensitive_field(key):
                redacted[key] = "[REDACTED]"
            elif isinstance(value, str):
                redacted[key] = self._redact_pii_from_string(value)
            elif isinstance(value, dict):
                redacted[key] = self._redact_pii_from_dict(value)
            elif isinstance(value, list):
                redacted[key] = [
                    self._redact_pii_from_string(item) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                redacted[key] = value
        
        return redacted
    
    def _is_sensitive_field(self, field_name: str) -> bool:
        """Check if field name indicates sensitive data"""
        sensitive_fields = {
            'password', 'token', 'key', 'secret', 'ssn', 'social_security',
            'credit_card', 'card_number', 'email', 'phone', 'address'
        }
        return field_name.lower() in sensitive_fields
    
    def _redact_pii_from_string(self, text: str) -> str:
        """Basic PII redaction from string"""
        import re
        
        # Email redaction
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]', text)
        
        # Phone redaction
        text = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE]', text)
        
        # SSN redaction
        text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[SSN]', text)
        
        # Credit card redaction
        text = re.sub(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', '[CREDIT_CARD]', text)
        
        return text


# Exception classes
class EncryptionError(Exception):
    """Encryption operation failed"""
    pass


class DecryptionError(Exception):
    """Decryption operation failed"""
    pass


class AuthenticationError(Exception):
    """Authentication failed"""
    pass


# Global instances
encryption_manager = EncryptionManager()
pii_encryption = PIIEncryption(encryption_manager)
jwt_manager = JWTManager(os.getenv("SECRET_KEY", "default-secret-key"))
api_key_manager = APIKeyManager(encryption_manager)
secure_logger = SecureLogger(encryption_manager)
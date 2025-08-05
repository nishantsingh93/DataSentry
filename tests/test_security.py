import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from datasentry.security.encryption import (
    EncryptionManager, PIIEncryption, JWTManager, APIKeyManager,
    EncryptionError, DecryptionError
)
from datasentry.security.rbac import (
    RoleBasedAccessControl, Permission, EntityType, User, Role
)


class TestEncryptionManager:
    
    @pytest.fixture
    def encryption_manager(self):
        return EncryptionManager()
    
    def test_encrypt_decrypt_string(self, encryption_manager):
        """Test string encryption and decryption"""
        original_data = "sensitive information"
        
        encrypted = encryption_manager.encrypt_data(original_data)
        decrypted = encryption_manager.decrypt_to_string(encrypted)
        
        assert encrypted != original_data
        assert decrypted == original_data
    
    def test_encrypt_decrypt_dict(self, encryption_manager):
        """Test dictionary encryption and decryption"""
        original_data = {"ssn": "123-45-6789", "email": "test@example.com"}
        
        encrypted = encryption_manager.encrypt_data(original_data)
        decrypted = encryption_manager.decrypt_to_dict(encrypted)
        
        assert encrypted != json.dumps(original_data)
        assert decrypted == original_data
    
    def test_encrypt_decrypt_bytes(self, encryption_manager):
        """Test bytes encryption and decryption"""
        original_data = b"binary sensitive data"
        
        encrypted = encryption_manager.encrypt_data(original_data)
        decrypted = encryption_manager.decrypt_data(encrypted)
        
        assert encrypted != original_data.decode()
        assert decrypted == original_data
    
    def test_password_hashing(self, encryption_manager):
        """Test password hashing and verification"""
        password = "secure_password123"
        
        hashed = encryption_manager.hash_password(password)
        assert hashed != password
        
        # Verify correct password
        assert encryption_manager.verify_password(password, hashed)
        
        # Verify incorrect password
        assert not encryption_manager.verify_password("wrong_password", hashed)
    
    def test_key_generation_from_password(self, encryption_manager):
        """Test key generation from password"""
        password = "test_password"
        salt = b"test_salt_16byte"
        
        key1 = encryption_manager.generate_key_from_password(password, salt)
        key2 = encryption_manager.generate_key_from_password(password, salt)
        
        # Same password and salt should generate same key
        assert key1 == key2
        assert len(key1) == 32  # 256 bits
    
    def test_encrypt_with_custom_key(self, encryption_manager):
        """Test encryption with custom key"""
        data = "test data"
        key = encryption_manager.generate_key_from_password("test_password")
        
        encrypted = encryption_manager.encrypt_with_key(data, key)
        decrypted = encryption_manager.decrypt_with_key(encrypted, key)
        
        assert decrypted == data
    
    def test_invalid_decryption(self, encryption_manager):
        """Test decryption with invalid data"""
        with pytest.raises(DecryptionError):
            encryption_manager.decrypt_data("invalid_encrypted_data")


class TestPIIEncryption:
    
    @pytest.fixture
    def pii_encryption(self):
        encryption_manager = EncryptionManager()
        return PIIEncryption(encryption_manager)
    
    def test_encrypt_pii_detection_results(self, pii_encryption):
        """Test encryption of PII detection results"""
        detection_data = {
            "original_text": "My email is john@example.com",
            "detected_entities": [
                {
                    "entity_type": "EMAIL",
                    "text": "john@example.com",
                    "context": "My email is john@example.com and phone",
                    "confidence": 0.9
                }
            ],
            "risk_score": 0.8
        }
        
        encrypted = pii_encryption.encrypt_pii_detection(detection_data)
        
        # Sensitive fields should be encrypted
        assert encrypted["original_text"] != detection_data["original_text"]
        assert encrypted["detected_entities"][0]["text"] != "john@example.com"
        assert encrypted["detected_entities"][0]["context"] != detection_data["detected_entities"][0]["context"]
        
        # Non-sensitive fields should remain unchanged
        assert encrypted["risk_score"] == detection_data["risk_score"]
        assert encrypted["detected_entities"][0]["entity_type"] == "EMAIL"
    
    def test_decrypt_pii_detection_results(self, pii_encryption):
        """Test decryption of PII detection results"""
        original_data = {
            "original_text": "Contact me at secret@company.com",
            "detected_entities": [
                {
                    "entity_type": "EMAIL",
                    "text": "secret@company.com",
                    "context": "Contact me at secret@company.com for details"
                }
            ]
        }
        
        encrypted = pii_encryption.encrypt_pii_detection(original_data)
        decrypted = pii_encryption.decrypt_pii_detection(encrypted)
        
        assert decrypted["original_text"] == original_data["original_text"]
        assert decrypted["detected_entities"][0]["text"] == original_data["detected_entities"][0]["text"]
        assert decrypted["detected_entities"][0]["context"] == original_data["detected_entities"][0]["context"]


class TestJWTManager:
    
    @pytest.fixture
    def jwt_manager(self):
        return JWTManager("test_secret_key")
    
    def test_create_and_verify_token(self, jwt_manager):
        """Test JWT token creation and verification"""
        payload = {"user_id": "test_user", "role": "admin"}
        
        token = jwt_manager.create_access_token(payload)
        decoded_payload = jwt_manager.verify_token(token)
        
        assert decoded_payload is not None
        assert decoded_payload["user_id"] == "test_user"
        assert decoded_payload["role"] == "admin"
        assert "exp" in decoded_payload
        assert "iat" in decoded_payload
    
    def test_token_expiration(self, jwt_manager):
        """Test token expiration"""
        payload = {"user_id": "test_user"}
        expires_delta = timedelta(seconds=1)
        
        token = jwt_manager.create_access_token(payload, expires_delta)
        
        # Token should be valid immediately
        assert not jwt_manager.is_token_expired(token)
        
        # Token should be expired after waiting
        import time
        time.sleep(2)
        assert jwt_manager.is_token_expired(token)
    
    def test_invalid_token(self, jwt_manager):
        """Test verification of invalid token"""
        invalid_token = "invalid.jwt.token"
        
        decoded_payload = jwt_manager.verify_token(invalid_token)
        assert decoded_payload is None
    
    def test_refresh_token(self, jwt_manager):
        """Test refresh token creation"""
        user_id = "test_user"
        
        refresh_token = jwt_manager.create_refresh_token(user_id)
        decoded = jwt_manager.verify_token(refresh_token)
        
        assert decoded is not None
        assert decoded["sub"] == user_id
        assert decoded["type"] == "refresh"


class TestAPIKeyManager:
    
    @pytest.fixture
    def api_key_manager(self):
        encryption_manager = EncryptionManager()
        return APIKeyManager(encryption_manager)
    
    def test_generate_and_validate_api_key(self, api_key_manager):
        """Test API key generation and validation"""
        user_id = "test_user"
        permissions = ["read_data", "write_data"]
        
        api_key = api_key_manager.generate_api_key(user_id, permissions)
        
        assert api_key.startswith("ds_")
        
        # Validate the key
        key_data = api_key_manager.validate_api_key(api_key)
        
        assert key_data is not None
        assert key_data["user_id"] == user_id
        assert key_data["permissions"] == permissions
    
    def test_api_key_expiration(self, api_key_manager):
        """Test API key expiration"""
        user_id = "test_user"
        permissions = ["read_data"]
        expires_at = datetime.utcnow() + timedelta(seconds=1)
        
        api_key = api_key_manager.generate_api_key(user_id, permissions, expires_at)
        
        # Key should be valid immediately
        key_data = api_key_manager.validate_api_key(api_key)
        assert key_data is not None
        
        # Key should be expired after waiting
        import time
        time.sleep(2)
        key_data = api_key_manager.validate_api_key(api_key)
        assert key_data is None
    
    def test_revoke_api_key(self, api_key_manager):
        """Test API key revocation"""
        user_id = "test_user"
        permissions = ["read_data"]
        
        api_key = api_key_manager.generate_api_key(user_id, permissions)
        
        # Key should be valid
        key_data = api_key_manager.validate_api_key(api_key)
        assert key_data is not None
        
        # Revoke the key
        revoked = api_key_manager.revoke_api_key(api_key)
        assert revoked
        
        # Key should no longer be valid
        key_data = api_key_manager.validate_api_key(api_key)
        assert key_data is None
    
    def test_list_user_keys(self, api_key_manager):
        """Test listing API keys for user"""
        user_id = "test_user"
        
        # Generate multiple keys
        key1 = api_key_manager.generate_api_key(user_id, ["read"])
        key2 = api_key_manager.generate_api_key(user_id, ["write"])
        key3 = api_key_manager.generate_api_key("other_user", ["admin"])
        
        # List keys for test_user
        user_keys = api_key_manager.list_user_keys(user_id)
        
        assert len(user_keys) == 2
        permissions_list = [key["permissions"] for key in user_keys]
        assert ["read"] in permissions_list
        assert ["write"] in permissions_list
    
    def test_invalid_api_key_format(self, api_key_manager):
        """Test validation of invalid API key format"""
        invalid_keys = [
            "invalid_key",
            "wrong_prefix_key",
            "ds_invalid_format",
            ""
        ]
        
        for invalid_key in invalid_keys:
            key_data = api_key_manager.validate_api_key(invalid_key)
            assert key_data is None


class TestRoleBasedAccessControl:
    
    @pytest.fixture
    def rbac(self):
        return RoleBasedAccessControl()
    
    def test_default_roles_created(self, rbac):
        """Test that default roles are created"""
        expected_roles = ["guest", "user", "analyst", "developer", "security_officer", "admin"]
        
        for role_name in expected_roles:
            assert role_name in rbac.roles
            role = rbac.roles[role_name]
            assert isinstance(role, Role)
            assert len(role.permissions) > 0
    
    def test_create_custom_role(self, rbac):
        """Test creating custom role"""
        role_name = "custom_role"
        description = "Custom test role"
        permissions = {Permission.DETECT_PII, Permission.MASK_PII}
        
        role = rbac.create_role(role_name, description, permissions)
        
        assert role.name == role_name
        assert role.description == description
        assert role.permissions == permissions
        assert role_name in rbac.roles
    
    def test_duplicate_role_creation(self, rbac):
        """Test creating duplicate role raises error"""
        with pytest.raises(ValueError, match="already exists"):
            rbac.create_role("admin", "Duplicate admin", set())
    
    def test_create_user(self, rbac):
        """Test user creation"""
        user = rbac.create_user(
            user_id="test_user",
            username="testuser",
            email="test@example.com",
            roles={"user", "analyst"}
        )
        
        assert user.user_id == "test_user"
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.roles == {"user", "analyst"}
        assert user.is_active
    
    def test_get_user_permissions(self, rbac):
        """Test getting user permissions from roles"""
        # Create user with admin role
        rbac.create_user("admin_user", "admin", "admin@test.com", roles={"admin"})
        
        permissions = rbac.get_user_permissions("admin_user")
        
        # Admin should have all permissions
        assert len(permissions) == len(Permission)
        assert Permission.MANAGE_USERS in permissions
        assert Permission.SYSTEM_CONFIG in permissions
    
    def test_check_permission(self, rbac):
        """Test permission checking"""
        # Create user with specific role
        rbac.create_user("analyst_user", "analyst", "analyst@test.com", roles={"analyst"})
        
        # Should have analyst permissions
        assert rbac.check_permission("analyst_user", Permission.GENERATE_REPORTS)
        assert rbac.check_permission("analyst_user", Permission.VIEW_ANALYTICS)
        
        # Should not have admin permissions
        assert not rbac.check_permission("analyst_user", Permission.MANAGE_USERS)
    
    def test_role_hierarchy(self, rbac):
        """Test role inheritance"""
        # Admin should inherit all lower role permissions
        admin_permissions = rbac.get_role_permissions("admin")
        user_permissions = rbac.get_role_permissions("user")
        
        # Admin permissions should include all user permissions
        assert user_permissions.issubset(admin_permissions)
    
    def test_authorize_request(self, rbac):
        """Test request authorization"""
        rbac.create_user("test_user", "test", "test@test.com", roles={"developer"})
        
        # Should authorize valid request
        authorized = rbac.authorize_request(
            user_id="test_user",
            action=Permission.PROXY_REQUESTS,
            resource_type=EntityType.DETECTION
        )
        assert authorized
        
        # Should not authorize invalid request
        not_authorized = rbac.authorize_request(
            user_id="test_user",
            action=Permission.MANAGE_USERS,
            resource_type=EntityType.USER
        )
        assert not not_authorized
    
    def test_inactive_user_no_permissions(self, rbac):
        """Test that inactive users have no permissions"""
        rbac.create_user("inactive_user", "inactive", "inactive@test.com", roles={"admin"})
        rbac.update_user("inactive_user", is_active=False)
        
        permissions = rbac.get_user_permissions("inactive_user")
        assert len(permissions) == 0
        
        authorized = rbac.authorize_request(
            user_id="inactive_user",
            action=Permission.API_ACCESS,
            resource_type=EntityType.SYSTEM
        )
        assert not authorized
    
    def test_update_user_roles(self, rbac):
        """Test updating user roles"""
        rbac.create_user("update_user", "update", "update@test.com", roles={"user"})
        
        # Update roles
        rbac.update_user("update_user", roles={"admin", "security_officer"})
        
        updated_user = rbac.users["update_user"]
        assert updated_user.roles == {"admin", "security_officer"}
        
        # Should now have admin permissions
        assert rbac.check_permission("update_user", Permission.MANAGE_USERS)
    
    def test_update_role_permissions(self, rbac):
        """Test updating role permissions"""
        # Create custom role
        rbac.create_role("test_role", "Test role", {Permission.DETECT_PII})
        
        # Update permissions
        new_permissions = {Permission.DETECT_PII, Permission.MASK_PII, Permission.VIEW_POLICIES}
        rbac.update_role("test_role", permissions=new_permissions)
        
        updated_role = rbac.roles["test_role"]
        assert updated_role.permissions == new_permissions
    
    def test_delete_role(self, rbac):
        """Test role deletion"""
        # Create role
        rbac.create_role("deletable_role", "To be deleted", {Permission.DETECT_PII})
        assert "deletable_role" in rbac.roles
        
        # Delete role
        deleted = rbac.delete_role("deletable_role")
        assert deleted
        assert "deletable_role" not in rbac.roles
    
    def test_cannot_delete_role_in_use(self, rbac):
        """Test cannot delete role assigned to users"""
        # Create role and assign to user
        rbac.create_role("assigned_role", "Assigned to user", {Permission.DETECT_PII})
        rbac.create_user("role_user", "roleuser", "role@test.com", roles={"assigned_role"})
        
        # Should not be able to delete role
        with pytest.raises(ValueError, match="still assigned to users"):
            rbac.delete_role("assigned_role")
    
    def test_list_users_with_permission(self, rbac):
        """Test listing users with specific permission"""
        rbac.create_user("admin1", "admin1", "admin1@test.com", roles={"admin"})
        rbac.create_user("user1", "user1", "user1@test.com", roles={"user"})
        rbac.create_user("analyst1", "analyst1", "analyst1@test.com", roles={"analyst"})
        
        # Find users who can manage other users (should be admin only)
        admin_users = rbac.list_users_with_permission(Permission.MANAGE_USERS)
        assert "admin1" in admin_users
        assert "user1" not in admin_users
        assert "analyst1" not in admin_users
    
    def test_audit_user_access(self, rbac):
        """Test user access audit"""
        rbac.create_user("audit_user", "audit", "audit@test.com", roles={"analyst"})
        
        audit_data = rbac.audit_user_access("audit_user")
        
        assert audit_data["user_id"] == "audit_user"
        assert audit_data["username"] == "audit"
        assert audit_data["email"] == "audit@test.com"
        assert "analyst" in audit_data["roles"]
        assert len(audit_data["total_permissions"]) > 0
    
    def test_get_system_stats(self, rbac):
        """Test getting system statistics"""
        # Add some users
        rbac.create_user("stats_user1", "stats1", "stats1@test.com")
        rbac.create_user("stats_user2", "stats2", "stats2@test.com")
        
        stats = rbac.get_system_stats()
        
        assert "total_users" in stats
        assert "active_users" in stats
        assert "total_roles" in stats
        assert "total_permissions" in stats
        assert stats["total_permissions"] == len(Permission)


class TestSecureLogger:
    
    @pytest.fixture
    def secure_logger(self):
        from datasentry.security.encryption import SecureLogger, EncryptionManager
        encryption_manager = EncryptionManager()
        return SecureLogger(encryption_manager)
    
    def test_pii_redaction_in_logs(self, secure_logger):
        """Test that PII is redacted in log messages"""
        # Mock the logger to capture log calls
        with patch.object(secure_logger, 'logger') as mock_logger:
            secure_logger.log_with_pii_redaction(
                "info",
                "User login",
                email="user@example.com",
                phone="555-123-4567",
                message="Contact me at secret@company.com"
            )
            
            # Check that logger was called with redacted data
            mock_logger.info.assert_called_once()
            args, kwargs = mock_logger.info.call_args
            
            # Email should be redacted
            assert kwargs["email"] == "[REDACTED]"  # Field name based redaction
            assert "[EMAIL]" in kwargs["message"]  # Content based redaction
            assert "[PHONE]" in kwargs["message"]  # Phone redaction
    
    def test_sensitive_field_detection(self, secure_logger):
        """Test detection of sensitive field names"""
        assert secure_logger._is_sensitive_field("password")
        assert secure_logger._is_sensitive_field("EMAIL")
        assert secure_logger._is_sensitive_field("api_key")
        assert not secure_logger._is_sensitive_field("username")
        assert not secure_logger._is_sensitive_field("message")
    
    def test_nested_dict_redaction(self, secure_logger):
        """Test redaction in nested dictionaries"""
        nested_data = {
            "user": {
                "name": "John Doe",
                "email": "john@example.com",
                "credentials": {
                    "password": "secret123",
                    "api_key": "key123"
                }
            },
            "message": "Call me at (555) 123-4567"
        }
        
        redacted = secure_logger._redact_pii_from_dict(nested_data)
        
        assert redacted["user"]["name"] == "John Doe"  # Non-sensitive
        assert redacted["user"]["email"] == "[REDACTED]"  # Sensitive field
        assert redacted["user"]["credentials"]["password"] == "[REDACTED]"
        assert redacted["user"]["credentials"]["api_key"] == "[REDACTED]"
        assert "[PHONE]" in redacted["message"]  # Content redaction
from typing import Dict, List, Set, Optional, Any
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import structlog

logger = structlog.get_logger(__name__)


class Permission(Enum):
    """System permissions"""
    # Detection permissions
    DETECT_PII = "detect_pii"
    DETECT_BATCH = "detect_batch"
    VIEW_DETECTION_RESULTS = "view_detection_results"
    
    # Masking permissions
    MASK_PII = "mask_pii"
    MASK_BATCH = "mask_batch"
    VIEW_MASKED_DATA = "view_masked_data"
    
    # Policy permissions
    VIEW_POLICIES = "view_policies"
    EDIT_POLICIES = "edit_policies"
    CREATE_POLICIES = "create_policies"
    DELETE_POLICIES = "delete_policies"
    
    # Proxy permissions
    PROXY_REQUESTS = "proxy_requests"
    VIEW_PROXY_LOGS = "view_proxy_logs"
    
    # Admin permissions
    MANAGE_USERS = "manage_users"
    MANAGE_ROLES = "manage_roles"
    VIEW_AUDIT_LOGS = "view_audit_logs"
    EXPORT_DATA = "export_data"
    SYSTEM_CONFIG = "system_config"
    
    # API permissions
    API_ACCESS = "api_access"
    API_ADMIN = "api_admin"
    
    # Reporting permissions
    GENERATE_REPORTS = "generate_reports"
    VIEW_ANALYTICS = "view_analytics"


class EntityType(Enum):
    """Resource entity types"""
    DETECTION = "detection"
    MASKING = "masking"
    POLICY = "policy"
    USER = "user"
    AUDIT_LOG = "audit_log"
    REPORT = "report"
    SYSTEM = "system"


@dataclass
class Role:
    """User role with permissions"""
    name: str
    description: str
    permissions: Set[Permission] = field(default_factory=set)
    inherits_from: Optional[str] = None
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class User:
    """System user"""
    user_id: str
    username: str
    email: str
    roles: Set[str] = field(default_factory=set)
    permissions: Set[Permission] = field(default_factory=set)  # Direct permissions
    is_active: bool = True
    last_login: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AccessContext:
    """Context for access control decisions"""
    user: User
    resource_type: EntityType
    resource_id: Optional[str] = None
    action: Permission = None
    request_metadata: Dict[str, Any] = field(default_factory=dict)


class RoleBasedAccessControl:
    """Enhanced RBAC system"""
    
    def __init__(self):
        self.roles: Dict[str, Role] = {}
        self.users: Dict[str, User] = {}
        self.role_hierarchy: Dict[str, Set[str]] = {}
        
        self._initialize_default_roles()
        self._setup_role_hierarchy()
    
    def _initialize_default_roles(self):
        """Initialize default system roles"""
        # Guest role - minimal permissions
        guest_role = Role(
            name="guest",
            description="Guest user with minimal access",
            permissions={
                Permission.API_ACCESS,
                Permission.DETECT_PII,
                Permission.VIEW_DETECTION_RESULTS
            }
        )
        
        # User role - standard user permissions
        user_role = Role(
            name="user",
            description="Standard user with basic PII operations",
            permissions={
                Permission.API_ACCESS,
                Permission.DETECT_PII,
                Permission.DETECT_BATCH,
                Permission.VIEW_DETECTION_RESULTS,
                Permission.MASK_PII,
                Permission.MASK_BATCH,
                Permission.VIEW_POLICIES
            }
        )
        
        # Analyst role - analysis and reporting
        analyst_role = Role(
            name="analyst",
            description="Data analyst with reporting capabilities",
            permissions={
                Permission.API_ACCESS,
                Permission.DETECT_PII,
                Permission.DETECT_BATCH,
                Permission.VIEW_DETECTION_RESULTS,
                Permission.MASK_PII,
                Permission.MASK_BATCH,
                Permission.VIEW_MASKED_DATA,
                Permission.VIEW_POLICIES,
                Permission.GENERATE_REPORTS,
                Permission.VIEW_ANALYTICS,
                Permission.VIEW_AUDIT_LOGS
            }
        )
        
        # Developer role - development and testing
        developer_role = Role(
            name="developer",
            description="Developer with API and testing access",
            permissions={
                Permission.API_ACCESS,
                Permission.DETECT_PII,
                Permission.DETECT_BATCH,
                Permission.VIEW_DETECTION_RESULTS,
                Permission.MASK_PII,
                Permission.MASK_BATCH,
                Permission.VIEW_MASKED_DATA,
                Permission.VIEW_POLICIES,
                Permission.PROXY_REQUESTS,
                Permission.VIEW_PROXY_LOGS
            }
        )
        
        # Security Officer role - security operations
        security_role = Role(
            name="security_officer",
            description="Security officer with policy management",
            permissions={
                Permission.API_ACCESS,
                Permission.DETECT_PII,
                Permission.DETECT_BATCH,
                Permission.VIEW_DETECTION_RESULTS,
                Permission.MASK_PII,
                Permission.MASK_BATCH,
                Permission.VIEW_MASKED_DATA,
                Permission.VIEW_POLICIES,
                Permission.EDIT_POLICIES,
                Permission.CREATE_POLICIES,
                Permission.VIEW_AUDIT_LOGS,
                Permission.GENERATE_REPORTS,
                Permission.VIEW_ANALYTICS,
                Permission.EXPORT_DATA
            }
        )
        
        # Admin role - full system access
        admin_role = Role(
            name="admin",
            description="System administrator with full access",
            permissions=set(Permission)  # All permissions
        )
        
        # Store roles
        for role in [guest_role, user_role, analyst_role, developer_role, security_role, admin_role]:
            self.roles[role.name] = role
    
    def _setup_role_hierarchy(self):
        """Setup role inheritance hierarchy"""
        self.role_hierarchy = {
            "admin": {"security_officer", "developer", "analyst", "user", "guest"},
            "security_officer": {"analyst", "user", "guest"},
            "developer": {"user", "guest"},
            "analyst": {"user", "guest"},
            "user": {"guest"},
            "guest": set()
        }
    
    def create_role(
        self, 
        name: str, 
        description: str, 
        permissions: Set[Permission],
        inherits_from: Optional[str] = None
    ) -> Role:
        """Create new role"""
        if name in self.roles:
            raise ValueError(f"Role '{name}' already exists")
        
        role = Role(
            name=name,
            description=description,
            permissions=permissions,
            inherits_from=inherits_from
        )
        
        self.roles[name] = role
        
        logger.info("Role created", role_name=name, permissions=len(permissions))
        return role
    
    def update_role(
        self, 
        name: str, 
        permissions: Optional[Set[Permission]] = None,
        description: Optional[str] = None,
        is_active: Optional[bool] = None
    ) -> Role:
        """Update existing role"""
        if name not in self.roles:
            raise ValueError(f"Role '{name}' not found")
        
        role = self.roles[name]
        
        if permissions is not None:
            role.permissions = permissions
        if description is not None:
            role.description = description
        if is_active is not None:
            role.is_active = is_active
        
        role.updated_at = datetime.utcnow()
        
        logger.info("Role updated", role_name=name)
        return role
    
    def delete_role(self, name: str) -> bool:
        """Delete role"""
        if name not in self.roles:
            return False
        
        # Check if role is in use
        users_with_role = [
            user for user in self.users.values() 
            if name in user.roles
        ]
        
        if users_with_role:
            raise ValueError(f"Cannot delete role '{name}' - still assigned to users")
        
        del self.roles[name]
        logger.info("Role deleted", role_name=name)
        return True
    
    def create_user(
        self,
        user_id: str,
        username: str,
        email: str,
        roles: Set[str] = None,
        permissions: Set[Permission] = None
    ) -> User:
        """Create new user"""
        if user_id in self.users:
            raise ValueError(f"User '{user_id}' already exists")
        
        user = User(
            user_id=user_id,
            username=username,
            email=email,
            roles=roles or {"user"},  # Default role
            permissions=permissions or set()
        )
        
        self.users[user_id] = user
        
        logger.info("User created", user_id=user_id, username=username, roles=list(user.roles))
        return user
    
    def update_user(
        self,
        user_id: str,
        roles: Optional[Set[str]] = None,
        permissions: Optional[Set[Permission]] = None,
        is_active: Optional[bool] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> User:
        """Update user"""
        if user_id not in self.users:
            raise ValueError(f"User '{user_id}' not found")
        
        user = self.users[user_id]
        
        if roles is not None:
            # Validate roles exist
            invalid_roles = roles - set(self.roles.keys())
            if invalid_roles:
                raise ValueError(f"Invalid roles: {invalid_roles}")
            user.roles = roles
        
        if permissions is not None:
            user.permissions = permissions
        
        if is_active is not None:
            user.is_active = is_active
        
        if metadata is not None:
            user.metadata.update(metadata)
        
        logger.info("User updated", user_id=user_id)
        return user
    
    def get_user_permissions(self, user_id: str) -> Set[Permission]:
        """Get all permissions for user (roles + direct permissions)"""
        if user_id not in self.users:
            return set()
        
        user = self.users[user_id]
        if not user.is_active:
            return set()
        
        all_permissions = set(user.permissions)
        
        # Add permissions from roles
        for role_name in user.roles:
            if role_name in self.roles:
                role = self.roles[role_name]
                if role.is_active:
                    all_permissions.update(role.permissions)
                    
                    # Add inherited permissions
                    inherited_permissions = self._get_inherited_permissions(role_name)
                    all_permissions.update(inherited_permissions)
        
        return all_permissions
    
    def _get_inherited_permissions(self, role_name: str) -> Set[Permission]:
        """Get permissions inherited from parent roles"""
        permissions = set()
        
        if role_name in self.role_hierarchy:
            for inherited_role in self.role_hierarchy[role_name]:
                if inherited_role in self.roles:
                    role = self.roles[inherited_role]
                    if role.is_active:
                        permissions.update(role.permissions)
        
        return permissions
    
    def check_permission(
        self, 
        user_id: str, 
        permission: Permission,
        context: Optional[AccessContext] = None
    ) -> bool:
        """Check if user has specific permission"""
        user_permissions = self.get_user_permissions(user_id)
        
        # Check direct permission
        if permission in user_permissions:
            return True
        
        # Check admin override
        if Permission.API_ADMIN in user_permissions:
            return True
        
        # Context-based permission checks
        if context:
            return self._check_contextual_permission(user_id, permission, context)
        
        return False
    
    def _check_contextual_permission(
        self,
        user_id: str,
        permission: Permission,
        context: AccessContext
    ) -> bool:
        """Check contextual permissions based on resource ownership, etc."""
        # Resource ownership checks
        if context.resource_type == EntityType.USER and context.resource_id == user_id:
            # Users can manage their own data
            if permission in {Permission.VIEW_DETECTION_RESULTS, Permission.EXPORT_DATA}:
                return True
        
        # Time-based access (example: only during business hours)
        if hasattr(context, 'time_restricted') and context.request_metadata.get('time_restricted'):
            current_hour = datetime.now().hour
            if not (9 <= current_hour <= 17):  # Business hours
                return False
        
        return False
    
    def authorize_request(
        self,
        user_id: str,
        action: Permission,
        resource_type: EntityType,
        resource_id: Optional[str] = None,
        request_metadata: Dict[str, Any] = None
    ) -> bool:
        """Authorize user request"""
        if user_id not in self.users:
            logger.warning("Authorization failed - user not found", user_id=user_id)
            return False
        
        user = self.users[user_id]
        if not user.is_active:
            logger.warning("Authorization failed - user inactive", user_id=user_id)
            return False
        
        context = AccessContext(
            user=user,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            request_metadata=request_metadata or {}
        )
        
        authorized = self.check_permission(user_id, action, context)
        
        if authorized:
            # Update last access time
            user.last_login = datetime.utcnow()
            
            logger.info(
                "Authorization granted",
                user_id=user_id,
                action=action.value,
                resource_type=resource_type.value
            )
        else:
            logger.warning(
                "Authorization denied",
                user_id=user_id,
                action=action.value,
                resource_type=resource_type.value
            )
        
        return authorized
    
    def get_user_roles(self, user_id: str) -> Set[str]:
        """Get user roles"""
        if user_id not in self.users:
            return set()
        return self.users[user_id].roles
    
    def get_role_permissions(self, role_name: str) -> Set[Permission]:
        """Get permissions for role"""
        if role_name not in self.roles:
            return set()
        
        role = self.roles[role_name]
        permissions = set(role.permissions)
        
        # Add inherited permissions
        permissions.update(self._get_inherited_permissions(role_name))
        
        return permissions
    
    def list_users_with_permission(self, permission: Permission) -> List[str]:
        """List users with specific permission"""
        users_with_permission = []
        
        for user_id in self.users:
            if self.check_permission(user_id, permission):
                users_with_permission.append(user_id)
        
        return users_with_permission
    
    def audit_user_access(self, user_id: str) -> Dict[str, Any]:
        """Generate access audit for user"""
        if user_id not in self.users:
            return {}
        
        user = self.users[user_id]
        user_permissions = self.get_user_permissions(user_id)
        
        return {
            "user_id": user_id,
            "username": user.username,
            "email": user.email,
            "is_active": user.is_active,
            "roles": list(user.roles),
            "direct_permissions": [p.value for p in user.permissions],
            "total_permissions": [p.value for p in user_permissions],
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "created_at": user.created_at.isoformat(),
            "metadata": user.metadata
        }
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get RBAC system statistics"""
        active_users = sum(1 for user in self.users.values() if user.is_active)
        active_roles = sum(1 for role in self.roles.values() if role.is_active)
        
        return {
            "total_users": len(self.users),
            "active_users": active_users,
            "total_roles": len(self.roles),
            "active_roles": active_roles,
            "total_permissions": len(Permission),
            "role_hierarchy_depth": max(len(descendants) for descendants in self.role_hierarchy.values())
        }


class PermissionValidator:
    """Validates permission requirements for API endpoints"""
    
    def __init__(self, rbac: RoleBasedAccessControl):
        self.rbac = rbac
    
    def require_permission(self, permission: Permission):
        """Decorator to require specific permission"""
        def decorator(func):
            def wrapper(*args, **kwargs):
                # Extract user_id from context (implementation depends on your auth system)
                user_id = self._extract_user_id_from_context()
                
                if not self.rbac.check_permission(user_id, permission):
                    from fastapi import HTTPException
                    raise HTTPException(
                        status_code=403,
                        detail=f"Permission required: {permission.value}"
                    )
                
                return func(*args, **kwargs)
            
            return wrapper
        return decorator
    
    def require_any_permission(self, permissions: List[Permission]):
        """Decorator to require any of the specified permissions"""
        def decorator(func):
            def wrapper(*args, **kwargs):
                user_id = self._extract_user_id_from_context()
                
                has_permission = any(
                    self.rbac.check_permission(user_id, perm) 
                    for perm in permissions
                )
                
                if not has_permission:
                    from fastapi import HTTPException
                    raise HTTPException(
                        status_code=403,
                        detail=f"One of these permissions required: {[p.value for p in permissions]}"
                    )
                
                return func(*args, **kwargs)
            
            return wrapper
        return decorator
    
    def _extract_user_id_from_context(self) -> str:
        """Extract user ID from request context - implementation specific"""
        # This would be implemented based on your authentication system
        # For example, from JWT token, session, etc.
        return "default_user"  # Placeholder


# Global RBAC instance
rbac_system = RoleBasedAccessControl()
permission_validator = PermissionValidator(rbac_system)
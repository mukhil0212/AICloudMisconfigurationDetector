import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from unittest.mock import MagicMock
import jwt
from datetime import datetime, timedelta

from app.auth import (
    User, UserRole, authenticate_user, create_access_token,
    verify_token, require_admin, require_authenticated
)

class TestAuth:
    """Test cases for authentication and authorization"""
    
    def test_authenticate_user_valid_credentials(self):
        """Test user authentication with valid credentials"""
        user = authenticate_user("admin", "admin123")
        
        assert user is not None
        assert user.username == "admin"
        assert user.role == UserRole.ADMIN
        assert user.email == "admin@company.com"
    
    def test_authenticate_user_invalid_username(self):
        """Test user authentication with invalid username"""
        user = authenticate_user("nonexistent", "password")
        assert user is None
    
    def test_authenticate_user_invalid_password(self):
        """Test user authentication with invalid password"""
        user = authenticate_user("admin", "wrongpassword")
        assert user is None
    
    def test_authenticate_user_viewer_role(self):
        """Test authentication for viewer role"""
        user = authenticate_user("viewer", "viewer123")
        
        assert user is not None
        assert user.username == "viewer"
        assert user.role == UserRole.VIEWER
        assert user.email == "viewer@company.com"
    
    def test_create_access_token(self):
        """Test JWT token creation"""
        token = create_access_token("testuser", UserRole.ADMIN)
        
        assert isinstance(token, str)
        assert len(token) > 0
        
        # Decode and verify token content
        from app.auth import JWT_SECRET, JWT_ALGORITHM
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        
        assert payload["sub"] == "testuser"
        assert payload["role"] == UserRole.ADMIN.value
        assert "exp" in payload
    
    def test_verify_token_valid(self):
        """Test token verification with valid token"""
        token = create_access_token("testuser", UserRole.ADMIN)
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        
        user = verify_token(credentials)
        
        assert user.username == "testuser"
        assert user.role == UserRole.ADMIN
    
    def test_verify_token_invalid(self):
        """Test token verification with invalid token"""
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="invalid-token")
        
        with pytest.raises(HTTPException) as exc_info:
            verify_token(credentials)
        
        assert exc_info.value.status_code == 401
        assert "Invalid token" in exc_info.value.detail
    
    def test_verify_token_expired(self):
        """Test token verification with expired token"""
        # Create an expired token
        from app.auth import JWT_SECRET, JWT_ALGORITHM
        payload = {
            "sub": "testuser",
            "role": UserRole.ADMIN.value,
            "exp": datetime.utcnow() - timedelta(hours=1)  # Expired 1 hour ago
        }
        expired_token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=expired_token)
        
        with pytest.raises(HTTPException) as exc_info:
            verify_token(credentials)
        
        assert exc_info.value.status_code == 401
        assert "Token expired" in exc_info.value.detail
    
    def test_require_admin_with_admin_user(self):
        """Test admin requirement with admin user"""
        admin_user = User(username="admin", role=UserRole.ADMIN)
        
        # Should not raise exception
        result = require_admin(admin_user)
        assert result == admin_user
    
    def test_require_admin_with_viewer_user(self):
        """Test admin requirement with viewer user"""
        viewer_user = User(username="viewer", role=UserRole.VIEWER)
        
        with pytest.raises(HTTPException) as exc_info:
            require_admin(viewer_user)
        
        assert exc_info.value.status_code == 403
        assert "Admin privileges required" in exc_info.value.detail
    
    def test_require_authenticated_with_valid_user(self):
        """Test authentication requirement with valid user"""
        user = User(username="testuser", role=UserRole.VIEWER)
        
        # Should not raise exception
        result = require_authenticated(user)
        assert result == user
    
    def test_user_roles_enum(self):
        """Test UserRole enum values"""
        assert UserRole.ADMIN.value == "admin"
        assert UserRole.VIEWER.value == "viewer"
        
        # Test that we can create UserRole from string
        assert UserRole("admin") == UserRole.ADMIN
        assert UserRole("viewer") == UserRole.VIEWER
from enum import Enum
from typing import Optional
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import jwt
import os
from datetime import datetime, timedelta

# Simple JWT secret (in production, use proper key management)
JWT_SECRET = os.environ.get("JWT_SECRET", "your-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"

security = HTTPBearer()

class UserRole(str, Enum):
    ADMIN = "admin"
    VIEWER = "viewer"

class User(BaseModel):
    username: str
    role: UserRole
    email: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str

# Mock user database (in production, use proper database)
MOCK_USERS = {
    "admin": {"password": "admin123", "role": UserRole.ADMIN, "email": "admin@company.com"},
    "viewer": {"password": "viewer123", "role": UserRole.VIEWER, "email": "viewer@company.com"},
    "security_analyst": {"password": "analyst123", "role": UserRole.VIEWER, "email": "analyst@company.com"}
}

def create_access_token(username: str, role: UserRole) -> str:
    """Create JWT access token"""
    payload = {
        "sub": username,
        "role": role.value,
        "exp": datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    """Verify JWT token and return user"""
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        role = payload.get("role")
        
        if username is None or role is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        return User(username=username, role=UserRole(role))
    
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_admin(current_user: User = Depends(verify_token)) -> User:
    """Require admin role"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=403, 
            detail="Admin privileges required for this operation"
        )
    return current_user

def require_authenticated(current_user: User = Depends(verify_token)) -> User:
    """Require any authenticated user"""
    return current_user

def authenticate_user(username: str, password: str) -> Optional[User]:
    """Authenticate user credentials"""
    user_data = MOCK_USERS.get(username)
    if user_data and user_data["password"] == password:
        return User(
            username=username,
            role=user_data["role"],
            email=user_data.get("email")
        )
    return None
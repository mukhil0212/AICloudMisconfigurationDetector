from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
from .scanner import scan_all, scan_with_credentials
from .ai_suggestions import get_bulk_suggestions
from .auth import (
    User, UserRole, LoginRequest, 
    authenticate_user, create_access_token,
    require_admin, require_authenticated
)
from .analytics import AnalyticsService
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AWSCredentials(BaseModel):
    access_key_id: str
    secret_access_key: str
    region: Optional[str] = "us-east-1"

class ScanRequest(BaseModel):
    credentials: Optional[AWSCredentials] = None
    ai_confidence_threshold: Optional[float] = 0.7  # 0.0 = show all, 1.0 = only high confidence
    strictness_level: Optional[str] = "balanced"  # "lenient", "balanced", "strict"

@app.get("/")
def read_root():
    return {"message": "AI Cloud Misconfiguration Detector Backend is running."}

@app.post("/auth/login")
def login(request: LoginRequest):
    """Authenticate user and return JWT token"""
    user = authenticate_user(request.username, request.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_access_token(user.username, user.role)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "username": user.username,
            "role": user.role.value,
            "email": user.email
        }
    }

@app.get("/auth/me")
def get_current_user(current_user: User = Depends(require_authenticated)):
    """Get current user information"""
    return {
        "username": current_user.username,
        "role": current_user.role.value,
        "email": current_user.email
    }

@app.get("/scan")
def run_scan():
    return scan_all()

@app.post("/scan")
def run_scan_with_credentials(
    request: ScanRequest, 
    current_user: User = Depends(require_authenticated)
):
    """Run scan with custom credentials - requires authentication"""
    if request.credentials:
        return scan_with_credentials(
            request.credentials.access_key_id,
            request.credentials.secret_access_key,
            request.credentials.region
        )
    else:
        return scan_all()

@app.post("/scan-with-suggestions")
def scan_with_ai_suggestions(
    request: ScanRequest,
    current_user: User = Depends(require_authenticated)
):
    """AI-powered scan with remediation suggestions - requires authentication"""
    try:
        print(f"User {current_user.username} ({current_user.role}) initiated scan")
        
        if request.credentials:
            print("Using provided credentials")
            misconfigs = scan_with_credentials(
                request.credentials.access_key_id,
                request.credentials.secret_access_key,
                request.credentials.region
            )
        else:
            print("Using default credentials/mock data")
            misconfigs = scan_all()
        
        print(f"Found {len(misconfigs)} misconfigurations")
        
        # Get AI suggestions for each misconfiguration with filtering
        suggestions = get_bulk_suggestions(
            misconfigs, 
            ai_confidence_threshold=request.ai_confidence_threshold or 0.7,
            strictness_level=request.strictness_level or "balanced"
        )
        print(f"Generated suggestions for {len(suggestions)} items (filtered by confidence threshold)")
        
        # Add metadata to suggestions
        for suggestion in suggestions:
            suggestion["can_remediate"] = current_user.role == UserRole.ADMIN
            suggestion["scanned_by"] = current_user.username
        
        # Record scan for analytics
        AnalyticsService.record_scan(
            user=current_user.username,
            misconfigurations=suggestions,
            scan_type="ai_powered"
        )
        
        return {
            "findings": suggestions,
            "scan_metadata": {
                "total_findings": len(suggestions),
                "scanned_by": current_user.username,
                "scan_type": "ai_powered",
                "timestamp": misconfigs[0].get("timestamp") if misconfigs else None
            }
        }
    
    except Exception as e:
        print(f"Error in scan_with_ai_suggestions: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/analytics/dashboard")
def get_analytics_dashboard(
    days: int = 30,
    current_user: User = Depends(require_authenticated)
):
    """Get analytics dashboard data"""
    return AnalyticsService.get_dashboard_metrics(days)

@app.post("/analytics/remediation")
def record_remediation_action(
    issue_id: str,
    action: str,
    current_user: User = Depends(require_admin)
):
    """Record a remediation action - admin only"""
    remediation_id = AnalyticsService.record_remediation(
        user=current_user.username,
        issue_id=issue_id,
        action=action,
        success=True  # Assume success for demo
    )
    return {"remediation_id": remediation_id, "status": "recorded"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

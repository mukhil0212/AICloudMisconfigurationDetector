from typing import Dict, List, Any
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import json

# In-memory storage for analytics (in production, use proper database)
scan_history = []
remediation_history = []

class AnalyticsService:
    
    @staticmethod
    def record_scan(user: str, misconfigurations: List[Dict], scan_type: str = "manual"):
        """Record a scan event for analytics"""
        scan_record = {
            "id": len(scan_history) + 1,
            "timestamp": datetime.utcnow().isoformat(),
            "user": user,
            "scan_type": scan_type,
            "total_issues": len(misconfigurations),
            "issues_by_service": AnalyticsService._categorize_by_service(misconfigurations),
            "issues_by_severity": AnalyticsService._categorize_by_severity(misconfigurations),
            "scan_duration_ms": 1500,  # Mock duration
            "findings": misconfigurations
        }
        scan_history.append(scan_record)
        return scan_record["id"]
    
    @staticmethod
    def record_remediation(user: str, issue_id: str, action: str, success: bool):
        """Record a remediation action"""
        remediation_record = {
            "id": len(remediation_history) + 1,
            "timestamp": datetime.utcnow().isoformat(),
            "user": user,
            "issue_id": issue_id,
            "action": action,
            "success": success,
            "time_to_remediation_hours": 0.5  # Mock time
        }
        remediation_history.append(remediation_record)
        return remediation_record["id"]
    
    @staticmethod
    def get_dashboard_metrics(days: int = 30) -> Dict[str, Any]:
        """Get comprehensive dashboard metrics"""
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        recent_scans = [
            scan for scan in scan_history 
            if datetime.fromisoformat(scan["timestamp"]) > cutoff_date
        ]
        recent_remediations = [
            rem for rem in remediation_history 
            if datetime.fromisoformat(rem["timestamp"]) > cutoff_date
        ]
        
        # Calculate metrics
        total_scans = len(recent_scans)
        total_issues = sum(scan["total_issues"] for scan in recent_scans)
        total_remediations = len(recent_remediations)
        successful_remediations = len([r for r in recent_remediations if r["success"]])
        
        # Service breakdown
        service_metrics = defaultdict(lambda: {"issues": 0, "scans": 0})
        for scan in recent_scans:
            for service, count in scan["issues_by_service"].items():
                service_metrics[service]["issues"] += count
                service_metrics[service]["scans"] += 1
        
        # Severity breakdown
        severity_metrics = defaultdict(int)
        for scan in recent_scans:
            for severity, count in scan["issues_by_severity"].items():
                severity_metrics[severity] += count
        
        # Time series data for charts
        daily_metrics = AnalyticsService._get_daily_metrics(recent_scans, days)
        
        # Average remediation time
        avg_remediation_time = (
            sum(r["time_to_remediation_hours"] for r in recent_remediations) / 
            len(recent_remediations) if recent_remediations else 0
        )
        
        return {
            "overview": {
                "total_scans": total_scans,
                "total_issues": total_issues,
                "total_remediations": total_remediations,
                "remediation_success_rate": (
                    successful_remediations / total_remediations * 100 
                    if total_remediations > 0 else 0
                ),
                "avg_remediation_time_hours": round(avg_remediation_time, 2),
                "avg_issues_per_scan": round(total_issues / total_scans, 1) if total_scans > 0 else 0
            },
            "service_breakdown": dict(service_metrics),
            "severity_breakdown": dict(severity_metrics),
            "time_series": daily_metrics,
            "recent_scans": recent_scans[-10:],  # Last 10 scans
            "top_issues": AnalyticsService._get_top_issues(recent_scans)
        }
    
    @staticmethod
    def _categorize_by_service(misconfigurations: List[Dict]) -> Dict[str, int]:
        """Categorize issues by AWS service"""
        service_count = defaultdict(int)
        for issue in misconfigurations:
            issue_type = issue.get("type", "")
            if "S3" in issue_type:
                service_count["S3"] += 1
            elif "IAM" in issue_type:
                service_count["IAM"] += 1
            elif "Security Group" in issue_type:
                service_count["EC2"] += 1
            else:
                service_count["Other"] += 1
        return dict(service_count)
    
    @staticmethod
    def _categorize_by_severity(misconfigurations: List[Dict]) -> Dict[str, int]:
        """Categorize issues by severity"""
        severity_count = defaultdict(int)
        for issue in misconfigurations:
            issue_type = issue.get("type", "")
            if "Public" in issue_type or "Unrestricted" in issue_type:
                severity_count["High"] += 1
            elif "IAM" in issue_type or "Permissive" in issue_type:
                severity_count["Medium"] += 1
            else:
                severity_count["Low"] += 1
        return dict(severity_count)
    
    @staticmethod
    def _get_daily_metrics(scans: List[Dict], days: int) -> List[Dict]:
        """Get daily metrics for time series charts"""
        daily_data = defaultdict(lambda: {"scans": 0, "issues": 0})
        
        for scan in scans:
            date = datetime.fromisoformat(scan["timestamp"]).date().isoformat()
            daily_data[date]["scans"] += 1
            daily_data[date]["issues"] += scan["total_issues"]
        
        # Fill in missing days with zeros
        result = []
        for i in range(days):
            date = (datetime.utcnow() - timedelta(days=i)).date().isoformat()
            result.append({
                "date": date,
                "scans": daily_data[date]["scans"],
                "issues": daily_data[date]["issues"]
            })
        
        return sorted(result, key=lambda x: x["date"])
    
    @staticmethod
    def _get_top_issues(scans: List[Dict]) -> List[Dict]:
        """Get most common issue types"""
        issue_types = []
        for scan in scans:
            for finding in scan.get("findings", []):
                issue_types.append(finding.get("type", "Unknown"))
        
        counter = Counter(issue_types)
        return [
            {"type": issue_type, "count": count} 
            for issue_type, count in counter.most_common(10)
        ]

# Add some mock data for demonstration
def populate_mock_analytics():
    """Populate with mock analytics data for demonstration"""
    mock_misconfigs = [
        {"type": "Public S3 Bucket", "resource_id": "bucket-1", "details": "Publicly accessible"},
        {"type": "Overly Permissive IAM Role", "resource_id": "role-1", "details": "Admin access"},
        {"type": "Unrestricted Security Group", "resource_id": "sg-1", "details": "0.0.0.0/0 access"}
    ]
    
    # Create some historical data
    for i in range(15):
        days_ago = datetime.utcnow() - timedelta(days=i)
        scan_record = {
            "id": i + 1,
            "timestamp": days_ago.isoformat(),
            "user": "admin" if i % 3 == 0 else "security_analyst",
            "scan_type": "automated" if i % 4 == 0 else "manual",
            "total_issues": len(mock_misconfigs) + (i % 3),
            "issues_by_service": {"S3": 1, "IAM": 1, "EC2": 1 + (i % 2)},
            "issues_by_severity": {"High": 1 + (i % 2), "Medium": 1, "Low": i % 3},
            "scan_duration_ms": 1200 + (i * 100),
            "findings": mock_misconfigs
        }
        scan_history.append(scan_record)
    
    # Create some remediation data
    for i in range(8):
        days_ago = datetime.utcnow() - timedelta(days=i, hours=i*2)
        remediation_record = {
            "id": i + 1,
            "timestamp": days_ago.isoformat(),
            "user": "admin",
            "issue_id": f"issue-{i+1}",
            "action": "remediated",
            "success": i % 4 != 0,  # 75% success rate
            "time_to_remediation_hours": 0.5 + (i * 0.3)
        }
        remediation_history.append(remediation_record)

# Initialize with mock data
populate_mock_analytics()
import pytest
from app.scanner import (
    find_public_s3_buckets,
    find_permissive_iam_roles,
    find_unrestricted_security_groups,
    scan_all,
    scan_with_credentials
)

class TestScanner:
    """Test cases for cloud security scanner"""
    
    def test_find_public_s3_buckets_no_credentials(self):
        """Test S3 scanning returns mock data when no credentials provided"""
        result = find_public_s3_buckets()
        
        assert len(result) == 1
        assert result[0]["type"] == "Public S3 Bucket"
        assert result[0]["resource_id"] == "mock-bucket-123"
        assert "mock data" in result[0]["details"]
    
    def test_find_permissive_iam_roles_no_credentials(self):
        """Test IAM scanning returns mock data when no credentials provided"""
        result = find_permissive_iam_roles()
        
        assert len(result) == 1
        assert result[0]["type"] == "Overly Permissive IAM Role"
        assert result[0]["resource_id"] == "mock-role-abc"
        assert "mock data" in result[0]["details"]
    
    def test_find_unrestricted_security_groups_no_credentials(self):
        """Test security group scanning returns mock data when no credentials provided"""
        result = find_unrestricted_security_groups()
        
        assert len(result) == 1
        assert result[0]["type"] == "Unrestricted Security Group"
        assert result[0]["resource_id"] == "sg-mock123"
        assert "mock data" in result[0]["details"]
    
    def test_scan_all(self):
        """Test full scan returns all mock data"""
        result = scan_all()
        
        assert len(result) == 3  # S3 + IAM + Security Group
        
        # Check each type is present
        types = [item["type"] for item in result]
        assert "Public S3 Bucket" in types
        assert "Overly Permissive IAM Role" in types
        assert "Unrestricted Security Group" in types
    
    def test_scan_with_invalid_credentials(self):
        """Test scanning with invalid credentials returns mock data"""
        result = scan_with_credentials("invalid", "invalid", "us-east-1")
        
        assert len(result) == 3
        for item in result:
            assert "mock data" in item["details"]
    
    def test_scan_with_empty_credentials(self):
        """Test scanning with empty credentials returns mock data"""
        result = scan_with_credentials("", "", "us-east-1")
        
        assert len(result) == 3
        for item in result:
            assert "mock data" in item["details"]
    
    def test_scan_all_returns_consistent_structure(self):
        """Test that all scan results have consistent structure"""
        result = scan_all()
        
        for item in result:
            assert "type" in item
            assert "resource_id" in item
            assert "details" in item
            assert isinstance(item["type"], str)
            assert isinstance(item["resource_id"], str)
            assert isinstance(item["details"], str)
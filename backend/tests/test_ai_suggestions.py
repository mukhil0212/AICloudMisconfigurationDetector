import pytest
from unittest.mock import patch, MagicMock
from app.ai_suggestions import (
    get_remediation_suggestions,
    get_bulk_suggestions,
    calculate_confidence_score
)

class TestAISuggestions:
    """Test cases for AI suggestions functionality"""
    
    def test_calculate_confidence_score_high_risk(self):
        """Test confidence score calculation for high risk issues"""
        misconfiguration = {
            "type": "Public S3 Bucket",
            "resource_id": "bucket-123"
        }
        
        score = calculate_confidence_score(misconfiguration, "balanced")
        assert score >= 0.8  # Should be high confidence for public resources
    
    def test_calculate_confidence_score_medium_risk(self):
        """Test confidence score calculation for medium risk issues"""
        misconfiguration = {
            "type": "Overly Permissive IAM Role",
            "resource_id": "role-123"
        }
        
        score = calculate_confidence_score(misconfiguration, "balanced")
        assert 0.6 <= score < 0.8  # Should be medium confidence
    
    def test_calculate_confidence_score_low_risk(self):
        """Test confidence score calculation for low risk issues"""
        misconfiguration = {
            "type": "Some Other Issue",
            "resource_id": "resource-123"
        }
        
        score = calculate_confidence_score(misconfiguration, "balanced")
        assert 0.5 <= score < 0.7  # Should be lower confidence
    
    def test_calculate_confidence_score_strict_mode(self):
        """Test confidence score in strict mode"""
        misconfiguration = {
            "type": "Public S3 Bucket",
            "resource_id": "bucket-123"
        }
        
        balanced_score = calculate_confidence_score(misconfiguration, "balanced")
        strict_score = calculate_confidence_score(misconfiguration, "strict")
        
        assert strict_score > balanced_score
    
    def test_calculate_confidence_score_lenient_mode(self):
        """Test confidence score in lenient mode"""
        misconfiguration = {
            "type": "Public S3 Bucket", 
            "resource_id": "bucket-123"
        }
        
        balanced_score = calculate_confidence_score(misconfiguration, "balanced")
        lenient_score = calculate_confidence_score(misconfiguration, "lenient")
        
        assert lenient_score < balanced_score
    
    def test_confidence_score_bounds(self):
        """Test confidence score is always between 0 and 1"""
        misconfiguration = {
            "type": "Public S3 Bucket",
            "resource_id": "bucket-123"
        }
        
        for strictness in ["lenient", "balanced", "strict"]:
            score = calculate_confidence_score(misconfiguration, strictness)
            assert 0.0 <= score <= 1.0
    
    @patch('app.ai_suggestions.client')
    def test_get_remediation_suggestions_success(self, mock_client):
        """Test successful AI suggestion generation"""
        # Mock the Groq API response
        mock_response = MagicMock()
        mock_response.choices[0].message.content = "## Security Risk\nThis is a test suggestion"
        mock_client.chat.completions.create.return_value = mock_response
        
        misconfiguration = {
            "type": "Public S3 Bucket",
            "resource_id": "bucket-123",
            "details": "Publicly accessible bucket"
        }
        
        result = get_remediation_suggestions(misconfiguration)
        
        assert "suggestion" in result
        assert "confidence" in result
        assert result["suggestion"] == "## Security Risk\nThis is a test suggestion"
        assert result["confidence"] == "high"  # Public bucket = high confidence
    
    @patch('app.ai_suggestions.api_key', None)
    def test_get_remediation_suggestions_no_api_key(self):
        """Test AI suggestion when API key is missing"""
        misconfiguration = {
            "type": "Public S3 Bucket",
            "resource_id": "bucket-123",
            "details": "Publicly accessible bucket"
        }
        
        result = get_remediation_suggestions(misconfiguration)
        
        assert "suggestion" in result
        assert "confidence" in result
        assert "GROQ_API_KEY not configured" in result["suggestion"]
        assert result["confidence"] == "low"
    
    @patch('app.ai_suggestions.client')
    def test_get_remediation_suggestions_api_error(self, mock_client):
        """Test AI suggestion when API call fails"""
        mock_client.chat.completions.create.side_effect = Exception("API Error")
        
        misconfiguration = {
            "type": "Public S3 Bucket",
            "resource_id": "bucket-123",
            "details": "Publicly accessible bucket"
        }
        
        result = get_remediation_suggestions(misconfiguration)
        
        assert "suggestion" in result
        assert "confidence" in result
        assert "Unable to generate AI suggestion" in result["suggestion"]
        assert result["confidence"] == "low"
    
    @patch('app.ai_suggestions.get_remediation_suggestions')
    def test_get_bulk_suggestions_filtering(self, mock_get_suggestions):
        """Test bulk suggestions with confidence filtering"""
        mock_get_suggestions.return_value = {
            "suggestion": "Test suggestion",
            "confidence": "high"
        }
        
        misconfigurations = [
            {"type": "Public S3 Bucket", "resource_id": "bucket-1"},  # High confidence
            {"type": "Some Other Issue", "resource_id": "resource-1"}  # Low confidence
        ]
        
        # Test with high threshold (should filter out low confidence)
        results = get_bulk_suggestions(misconfigurations, ai_confidence_threshold=0.8)
        assert len(results) == 1  # Only high confidence item
        
        # Test with low threshold (should include all)
        results = get_bulk_suggestions(misconfigurations, ai_confidence_threshold=0.3)
        assert len(results) == 2  # Both items
    
    @patch('app.ai_suggestions.get_remediation_suggestions')
    def test_get_bulk_suggestions_structure(self, mock_get_suggestions):
        """Test bulk suggestions return proper structure"""
        mock_get_suggestions.return_value = {
            "suggestion": "Test suggestion",
            "confidence": "high"
        }
        
        misconfigurations = [
            {"type": "Public S3 Bucket", "resource_id": "bucket-1", "details": "Test"}
        ]
        
        results = get_bulk_suggestions(misconfigurations)
        
        assert len(results) == 1
        result = results[0]
        
        # Check original fields are preserved
        assert result["type"] == "Public S3 Bucket"
        assert result["resource_id"] == "bucket-1"
        assert result["details"] == "Test"
        
        # Check AI fields are added
        assert "ai_suggestion" in result
        assert "confidence" in result
        assert "confidence_score" in result
        assert "strictness_level" in result
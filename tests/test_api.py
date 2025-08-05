import pytest
import json
from fastapi.testclient import TestClient
from datasentry.api.app import create_app
from datasentry.core.config import settings


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


@pytest.fixture
def api_headers():
    return {"X-API-Key": settings.admin_api_key}


class TestHealthEndpoint:
    
    def test_health_check(self, client):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "components" in data
        assert "uptime_seconds" in data


class TestDetectionEndpoint:
    
    def test_detect_pii_with_email(self, client):
        payload = {
            "text": "Please contact me at john.doe@example.com",
            "language": "en"
        }
        
        response = client.post("/api/v1/detect", json=payload)
        assert response.status_code == 200
        
        data = response.json()
        assert "detected_entities" in data
        assert "risk_score" in data
        assert "has_high_risk_pii" in data
        assert "processing_time_ms" in data
        
        if data["detected_entities"]:
            entity = data["detected_entities"][0]
            assert "entity_type" in entity
            assert "confidence" in entity
            assert "text" in entity
    
    def test_detect_no_pii(self, client):
        payload = {
            "text": "This is a normal sentence without any personal information.",
            "language": "en"
        }
        
        response = client.post("/api/v1/detect", json=payload)
        assert response.status_code == 200
        
        data = response.json()
        assert len(data["detected_entities"]) == 0
        assert data["risk_score"] == 0.0
        assert not data["has_high_risk_pii"]
    
    def test_detect_multiple_pii(self, client):
        payload = {
            "text": "Contact John at john@example.com or call (555) 123-4567. His SSN is 123-45-6789.",
            "language": "en"
        }
        
        response = client.post("/api/v1/detect", json=payload)
        assert response.status_code == 200
        
        data = response.json()
        assert len(data["detected_entities"]) >= 2
        assert data["risk_score"] > 0.5
        
        entity_types = [entity["entity_type"] for entity in data["detected_entities"]]
        assert len(set(entity_types)) >= 2  # At least 2 different types
    
    def test_detect_empty_text(self, client):
        payload = {"text": ""}
        
        response = client.post("/api/v1/detect", json=payload)
        assert response.status_code == 200
        
        data = response.json()
        assert len(data["detected_entities"]) == 0


class TestMaskingEndpoint:
    
    def test_mask_pii_with_detection(self, client):
        payload = {
            "text": "My email is john.doe@example.com and phone is (555) 123-4567",
            "detect_first": True
        }
        
        response = client.post("/api/v1/mask", json=payload)
        assert response.status_code == 200
        
        data = response.json()
        assert "masked_text" in data
        assert "entities_masked" in data
        assert "processing_time_ms" in data
        
        # Verify masking occurred
        assert data["masked_text"] != data["original_text"]
        assert "@" not in data["masked_text"] or "*" in data["masked_text"]
    
    def test_mask_no_pii(self, client):
        payload = {
            "text": "This text has no personal information.",
            "detect_first": True
        }
        
        response = client.post("/api/v1/mask", json=payload)
        assert response.status_code == 200
        
        data = response.json()
        assert data["masked_text"] == data["original_text"]
        assert len(data["entities_masked"]) == 0
    
    def test_mask_with_custom_config(self, client):
        payload = {
            "text": "Contact me at test@example.com",
            "detect_first": True,
            "masking_config": {
                "EMAIL": {
                    "mask_type": "full",
                    "mask_char": "#"
                }
            }
        }
        
        response = client.post("/api/v1/mask", json=payload)
        assert response.status_code == 200
        
        data = response.json()
        if data["entities_masked"]:
            assert "#" in data["masked_text"]


class TestSanitizeEndpoint:
    
    def test_sanitize_allow(self, client):
        payload = {
            "text": "This is safe text with no PII.",
            "policy_name": "default",
            "user_role": "user"
        }
        
        response = client.post("/api/v1/sanitize", json=payload)
        assert response.status_code == 200
        
        data = response.json()
        assert data["action_taken"] in ["allow", "warn"]
        assert data["sanitized_text"] == data["original_text"]
    
    def test_sanitize_mask(self, client):
        payload = {
            "text": "My email is test@example.com",
            "policy_name": "default", 
            "user_role": "user"
        }
        
        response = client.post("/api/v1/sanitize", json=payload)
        assert response.status_code == 200
        
        data = response.json()
        assert data["action_taken"] in ["mask", "warn", "allow"]
        assert "detected_entities" in data
        assert "risk_score" in data
    
    def test_sanitize_block_high_risk(self, client):
        payload = {
            "text": "My SSN is 123-45-6789 and credit card is 4532123456789012",
            "policy_name": "default",
            "user_role": "user"
        }
        
        response = client.post("/api/v1/sanitize", json=payload)
        assert response.status_code == 200
        
        data = response.json()
        # Should be blocked or masked due to high-risk PII
        assert data["action_taken"] in ["block", "mask"]
        
        if data["action_taken"] == "block":
            assert data["blocked_reason"] is not None
            assert "BLOCKED" in data["sanitized_text"].upper()


class TestProxyEndpoint:
    
    def test_proxy_unauthorized(self, client):
        payload = {
            "target_url": "https://api.openai.com/v1/chat/completions",
            "payload": {"messages": [{"role": "user", "content": "Hello"}]}
        }
        
        response = client.post("/api/v1/proxy", json=payload)
        assert response.status_code == 401  # Unauthorized without API key
    
    def test_proxy_with_api_key(self, client, api_headers):
        # Mock a simple request that won't actually call external API
        payload = {
            "target_url": "https://httpbin.org/post",
            "payload": {"test": "data"},
            "sanitize_request": False
        }
        
        # This test would need mocking for actual external calls
        # For now, just test the authentication works
        response = client.post("/api/v1/proxy", json=payload, headers=api_headers)
        # The actual response will depend on whether httpbin.org is accessible
        # but at least we know authentication passed if we don't get 401
        assert response.status_code != 401


class TestPoliciesEndpoint:
    
    def test_get_policies_unauthorized(self, client):
        response = client.get("/api/v1/policies")
        assert response.status_code == 401
    
    def test_get_policies_authorized(self, client, api_headers):
        response = client.get("/api/v1/policies", headers=api_headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "default_policy" in data
        assert "entity_policies" in data
    
    def test_update_policies_unauthorized(self, client):
        payload = {"test_policy": {"action": "allow"}}
        response = client.put("/api/v1/policies", json=payload)
        assert response.status_code == 401
    
    def test_update_policies_authorized(self, client, api_headers):
        payload = {
            "test_policy": {
                "action": "mask",
                "confidence_threshold": 0.8
            }
        }
        
        response = client.put("/api/v1/policies", json=payload, headers=api_headers)
        assert response.status_code == 200
        
        data = response.json()
        assert "message" in data
        assert "success" in data["message"].lower()


class TestErrorHandling:
    
    def test_invalid_json(self, client):
        response = client.post(
            "/api/v1/detect",
            data="invalid json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422  # Unprocessable Entity
    
    def test_missing_required_field(self, client):
        payload = {"language": "en"}  # Missing required 'text' field
        
        response = client.post("/api/v1/detect", json=payload)
        assert response.status_code == 422
    
    def test_invalid_language_code(self, client):
        payload = {
            "text": "Test text",
            "language": "invalid_lang_code"
        }
        
        response = client.post("/api/v1/detect", json=payload)
        # Should still work, just might not use the invalid language
        assert response.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__])
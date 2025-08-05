import pytest
from datasentry.detection.detector import PIIDetector, PIIDetection
from datasentry.detection.patterns import PIIType, CustomPIIPatterns


class TestPIIDetector:
    
    @pytest.fixture
    def detector(self):
        return PIIDetector(enable_custom_patterns=True, enable_ner_models=False)
    
    def test_email_detection(self, detector):
        text = "Please contact me at john.doe@example.com for more information."
        result = detector.detect_pii(text)
        
        assert len(result.detected_entities) >= 1
        email_entities = [e for e in result.detected_entities if e.entity_type == "EMAIL"]
        assert len(email_entities) >= 1
        assert "john.doe@example.com" in email_entities[0].text
    
    def test_phone_detection(self, detector):
        text = "Call me at (555) 123-4567 or 555-987-6543."
        result = detector.detect_pii(text)
        
        phone_entities = [e for e in result.detected_entities if e.entity_type == "PHONE_NUMBER"]
        assert len(phone_entities) >= 1
    
    def test_ssn_detection(self, detector):
        text = "My social security number is 123-45-6789."
        result = detector.detect_pii(text)
        
        ssn_entities = [e for e in result.detected_entities if e.entity_type == "US_SSN"]
        assert len(ssn_entities) >= 1
        assert "123-45-6789" in ssn_entities[0].text
    
    def test_credit_card_detection(self, detector):
        text = "My credit card number is 4532-1234-5678-9012."
        result = detector.detect_pii(text)
        
        cc_entities = [e for e in result.detected_entities if "CREDIT_CARD" in e.entity_type]
        assert len(cc_entities) >= 1
    
    def test_ip_address_detection(self, detector):
        text = "The server IP is 192.168.1.100."
        result = detector.detect_pii(text)
        
        ip_entities = [e for e in result.detected_entities if e.entity_type == "IP_ADDRESS"]
        assert len(ip_entities) >= 1
        assert "192.168.1.100" in ip_entities[0].text
    
    def test_aws_key_detection(self, detector):
        text = "AWS key: AKIAIOSFODNN7EXAMPLE"
        result = detector.detect_pii(text)
        
        aws_entities = [e for e in result.detected_entities if e.entity_type == "AWS_ACCESS_KEY"]
        assert len(aws_entities) >= 1
    
    def test_no_pii_text(self, detector):
        text = "This is a normal sentence with no personal information."
        result = detector.detect_pii(text)
        
        assert len(result.detected_entities) == 0
        assert result.risk_score == 0.0
        assert not result.has_high_risk_pii
    
    def test_multiple_pii_types(self, detector):
        text = "Contact John at john@example.com or call (555) 123-4567. SSN: 123-45-6789"
        result = detector.detect_pii(text)
        
        assert len(result.detected_entities) >= 3
        assert result.risk_score > 0.5
        
        entity_types = [e.entity_type for e in result.detected_entities]
        assert "EMAIL" in entity_types or any("EMAIL" in t for t in entity_types)
    
    def test_risk_score_calculation(self, detector):
        # High risk text
        high_risk_text = "SSN: 123-45-6789, Credit Card: 4532123456789012"
        high_risk_result = detector.detect_pii(high_risk_text)
        
        # Low risk text  
        low_risk_text = "Contact me at john@example.com"
        low_risk_result = detector.detect_pii(low_risk_text)
        
        assert high_risk_result.risk_score > low_risk_result.risk_score
        assert high_risk_result.has_high_risk_pii
        assert not low_risk_result.has_high_risk_pii
    
    def test_context_extraction(self, detector):
        text = "My personal email address is confidential@company.com and should not be shared."
        result = detector.detect_pii(text)
        
        email_entities = [e for e in result.detected_entities if "EMAIL" in e.entity_type]
        if email_entities:
            assert len(email_entities[0].context) > len(email_entities[0].text)
            assert "confidential@company.com" in email_entities[0].context


class TestCustomPIIPatterns:
    
    def test_email_patterns(self):
        patterns = CustomPIIPatterns.get_patterns_for_type(PIIType.EMAIL)
        assert len(patterns) > 0
        
        test_emails = [
            "test@example.com",
            "user.name+tag@domain.co.uk",
            "first.last@subdomain.example.org"
        ]
        
        for email in test_emails:
            matches = any(pattern.search(email) for pattern in patterns)
            assert matches, f"Failed to match email: {email}"
    
    def test_phone_patterns(self):
        patterns = CustomPIIPatterns.get_patterns_for_type(PIIType.PHONE)
        assert len(patterns) > 0
        
        test_phones = [
            "(555) 123-4567",
            "555-123-4567", 
            "555.123.4567",
            "+1 555 123 4567"
        ]
        
        for phone in test_phones:
            matches = any(pattern.search(phone) for pattern in patterns)
            assert matches, f"Failed to match phone: {phone}"
    
    def test_context_keywords(self):
        # Test email context
        text_with_context = "Please send it to my email address"
        text_without_context = "The weather is nice today"
        
        assert CustomPIIPatterns.has_context_keywords(text_with_context, PIIType.EMAIL)
        assert not CustomPIIPatterns.has_context_keywords(text_without_context, PIIType.EMAIL)
    
    def test_ssn_patterns(self):
        patterns = CustomPIIPatterns.get_patterns_for_type(PIIType.SSN)
        
        valid_ssns = [
            "123-45-6789",
            "123 45 6789", 
            "123456789"
        ]
        
        for ssn in valid_ssns:
            matches = any(pattern.search(ssn) for pattern in patterns)
            assert matches, f"Failed to match SSN: {ssn}"


if __name__ == "__main__":
    pytest.main([__file__])
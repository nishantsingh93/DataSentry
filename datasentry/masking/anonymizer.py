from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
import hashlib
import random
import string
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import RecognizerResult, OperatorConfig

from ..detection.detector import PIIDetection, DetectionResult


class MaskingType(Enum):
    FULL = "full"
    PARTIAL = "partial"
    SYNTHETIC = "synthetic"
    HASH = "hash"
    REDACT = "redact"


@dataclass
class MaskingResult:
    original_text: str
    masked_text: str
    entities_masked: List[PIIDetection]
    masking_metadata: Dict[str, Any]


class PIIMasker:
    """PII masking and anonymization engine"""
    
    def __init__(self):
        self.anonymizer = AnonymizerEngine()
        self._synthetic_generators = self._setup_synthetic_generators()
    
    def _setup_synthetic_generators(self) -> Dict[str, callable]:
        """Setup synthetic data generators for different PII types"""
        return {
            "EMAIL": self._generate_synthetic_email,
            "PHONE_NUMBER": self._generate_synthetic_phone,
            "PERSON": self._generate_synthetic_name,
            "CREDIT_CARD": self._generate_synthetic_credit_card,
            "US_SSN": self._generate_synthetic_ssn,
            "IP_ADDRESS": self._generate_synthetic_ip,
        }
    
    def mask_pii(
        self, 
        detection_result: DetectionResult, 
        masking_config: Dict[str, Dict[str, Any]]
    ) -> MaskingResult:
        """
        Mask PII entities in text based on configuration
        
        Args:
            detection_result: Result from PII detection
            masking_config: Configuration for masking each entity type
            
        Returns:
            MaskingResult with masked text and metadata
        """
        if not detection_result.detected_entities:
            return MaskingResult(
                original_text=detection_result.original_text,
                masked_text=detection_result.original_text,
                entities_masked=[],
                masking_metadata={"entities_processed": 0}
            )
        
        masked_text = detection_result.original_text
        entities_masked = []
        masking_metadata = {"entities_processed": 0, "masking_methods": {}}
        
        # Sort entities by position (reverse order to maintain text positions)
        sorted_entities = sorted(
            detection_result.detected_entities, 
            key=lambda x: x.start, 
            reverse=True
        )
        
        for entity in sorted_entities:
            entity_config = masking_config.get(
                entity.entity_type, 
                masking_config.get("DEFAULT", {"mask_type": "full"})
            )
            
            mask_type = MaskingType(entity_config.get("mask_type", "full"))
            masked_value = self._apply_masking(entity, mask_type, entity_config)
            
            # Replace in text
            masked_text = (
                masked_text[:entity.start] + 
                masked_value + 
                masked_text[entity.end:]
            )
            
            entities_masked.append(entity)
            masking_metadata["entities_processed"] += 1
            masking_metadata["masking_methods"][entity.entity_type] = mask_type.value
        
        return MaskingResult(
            original_text=detection_result.original_text,
            masked_text=masked_text,
            entities_masked=entities_masked,
            masking_metadata=masking_metadata
        )
    
    def _apply_masking(
        self, 
        entity: PIIDetection, 
        mask_type: MaskingType, 
        config: Dict[str, Any]
    ) -> str:
        """Apply specific masking method to an entity"""
        
        if mask_type == MaskingType.FULL:
            return self._full_mask(entity, config)
        elif mask_type == MaskingType.PARTIAL:
            return self._partial_mask(entity, config)
        elif mask_type == MaskingType.SYNTHETIC:
            return self._synthetic_mask(entity, config)
        elif mask_type == MaskingType.HASH:
            return self._hash_mask(entity, config)
        elif mask_type == MaskingType.REDACT:
            return self._redact_mask(entity, config)
        else:
            return self._full_mask(entity, config)
    
    def _full_mask(self, entity: PIIDetection, config: Dict[str, Any]) -> str:
        """Replace entire entity with mask characters"""
        mask_char = config.get("mask_char", "*")
        mask_length = config.get("mask_length", len(entity.text))
        return mask_char * mask_length
    
    def _partial_mask(self, entity: PIIDetection, config: Dict[str, Any]) -> str:
        """Partially mask the entity, showing some characters"""
        text = entity.text
        mask_char = config.get("mask_char", "*")
        
        if entity.entity_type == "EMAIL":
            # Mask username but keep domain
            if "@" in text:
                username, domain = text.split("@", 1)
                masked_username = username[0] + mask_char * (len(username) - 1)
                return f"{masked_username}@{domain}"
        
        elif entity.entity_type == "PHONE_NUMBER":
            # Mask middle digits
            if len(text) >= 7:
                return text[:3] + mask_char * (len(text) - 6) + text[-3:]
        
        elif entity.entity_type == "CREDIT_CARD":
            # Show last 4 digits
            if len(text) >= 4:
                return mask_char * (len(text) - 4) + text[-4:]
        
        elif entity.entity_type == "US_SSN":
            # Show last 4 digits
            if len(text) >= 4:
                return mask_char * (len(text) - 4) + text[-4:]
        
        # Default partial masking: show first and last character
        if len(text) > 2:
            return text[0] + mask_char * (len(text) - 2) + text[-1]
        else:
            return mask_char * len(text)
    
    def _synthetic_mask(self, entity: PIIDetection, config: Dict[str, Any]) -> str:
        """Replace with synthetic but realistic data"""
        generator = self._synthetic_generators.get(entity.entity_type)
        if generator:
            return generator()
        else:
            return f"[SYNTHETIC_{entity.entity_type}]"
    
    def _hash_mask(self, entity: PIIDetection, config: Dict[str, Any]) -> str:
        """Replace with hash of the original value"""
        hash_algorithm = config.get("hash_algorithm", "sha256")
        salt = config.get("salt", "datasentry_salt")
        
        if hash_algorithm == "sha256":
            hash_object = hashlib.sha256((entity.text + salt).encode())
        else:
            hash_object = hashlib.md5((entity.text + salt).encode())
        
        hash_hex = hash_object.hexdigest()
        truncate_length = config.get("hash_length", 8)
        
        return f"[HASH_{hash_hex[:truncate_length].upper()}]"
    
    def _redact_mask(self, entity: PIIDetection, config: Dict[str, Any]) -> str:
        """Replace with redaction marker"""
        return f"[REDACTED_{entity.entity_type}]"
    
    # Synthetic data generators
    def _generate_synthetic_email(self) -> str:
        """Generate a synthetic email address"""
        domains = ["example.com", "test.org", "sample.net", "demo.co"]
        username = ''.join(random.choices(string.ascii_lowercase, k=8))
        domain = random.choice(domains)
        return f"{username}@{domain}"
    
    def _generate_synthetic_phone(self) -> str:
        """Generate a synthetic phone number"""
        return f"555-{random.randint(100, 999)}-{random.randint(1000, 9999)}"
    
    def _generate_synthetic_name(self) -> str:
        """Generate a synthetic person name"""
        first_names = ["John", "Jane", "Alex", "Sam", "Chris", "Jordan"]
        last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia"]
        return f"{random.choice(first_names)} {random.choice(last_names)}"
    
    def _generate_synthetic_credit_card(self) -> str:
        """Generate a synthetic credit card number"""
        return "4000-1234-5678-9012"  # Test Visa number
    
    def _generate_synthetic_ssn(self) -> str:
        """Generate a synthetic SSN"""
        return "000-12-3456"  # Invalid SSN for testing
    
    def _generate_synthetic_ip(self) -> str:
        """Generate a synthetic IP address"""
        return f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"


class PIIRedactor:
    """Simple redaction service for blocking sensitive content"""
    
    @staticmethod
    def should_block(detection_result: DetectionResult, block_threshold: float = 0.8) -> bool:
        """Determine if content should be blocked based on detection results"""
        if detection_result.has_high_risk_pii:
            return True
        
        if detection_result.risk_score >= block_threshold:
            return True
        
        # Block if too many PII entities detected
        if len(detection_result.detected_entities) > 5:
            return True
        
        return False
    
    @staticmethod
    def get_block_message(detection_result: DetectionResult) -> str:
        """Generate a block message explaining why content was blocked"""
        entity_types = [entity.entity_type for entity in detection_result.detected_entities]
        unique_types = list(set(entity_types))
        
        return (
            f"Content blocked due to sensitive information detection. "
            f"Detected PII types: {', '.join(unique_types)}. "
            f"Risk Score: {detection_result.risk_score:.2f}"
        )
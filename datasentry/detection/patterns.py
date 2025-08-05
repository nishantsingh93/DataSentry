import re
from typing import Dict, List, Pattern
from enum import Enum


class PIIType(Enum):
    EMAIL = "EMAIL"
    PHONE = "PHONE_NUMBER"
    SSN = "US_SSN"
    CREDIT_CARD = "CREDIT_CARD"
    IP_ADDRESS = "IP_ADDRESS"
    URL = "URL"
    DATE_TIME = "DATE_TIME"
    PERSON_NAME = "PERSON"
    LOCATION = "LOCATION"
    ORGANIZATION = "ORGANIZATION"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    PASSPORT = "PASSPORT"
    DRIVER_LICENSE = "DRIVER_LICENSE"
    AWS_ACCESS_KEY = "AWS_ACCESS_KEY"
    API_KEY = "API_KEY"
    PASSWORD = "PASSWORD"
    MEDICAL_RECORD = "MEDICAL_RECORD"


class CustomPIIPatterns:
    """Custom regex patterns for PII detection"""
    
    PATTERNS: Dict[PIIType, List[Pattern]] = {
        PIIType.EMAIL: [
            re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        ],
        PIIType.PHONE: [
            re.compile(r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'),
            re.compile(r'\b\d{3}-\d{3}-\d{4}\b'),
            re.compile(r'\(\d{3}\)\s?\d{3}-\d{4}'),
        ],
        PIIType.SSN: [
            re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            re.compile(r'\b\d{3}\s\d{2}\s\d{4}\b'),
            re.compile(r'\b\d{9}\b'),
        ],
        PIIType.CREDIT_CARD: [
            re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'),
        ],
        PIIType.IP_ADDRESS: [
            re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
        ],
        PIIType.URL: [
            re.compile(r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?'),
        ],
        PIIType.AWS_ACCESS_KEY: [
            re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
        ],
        PIIType.API_KEY: [
            re.compile(r'\b[A-Za-z0-9]{32,}\b'),
            re.compile(r'sk-[A-Za-z0-9]{48}'),
            re.compile(r'pk_[a-z]+_[A-Za-z0-9]{24}'),
        ],
        PIIType.BANK_ACCOUNT: [
            re.compile(r'\b\d{8,17}\b'),
        ],
        PIIType.PASSPORT: [
            re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'),
        ],
        PIIType.DRIVER_LICENSE: [
            re.compile(r'\b[A-Z]\d{7,8}\b'),
            re.compile(r'\b\d{8,9}\b'),
        ],
    }
    
    CONTEXT_KEYWORDS = {
        PIIType.EMAIL: ['email', 'e-mail', 'mail', 'contact'],
        PIIType.PHONE: ['phone', 'tel', 'mobile', 'cell', 'number'],
        PIIType.SSN: ['ssn', 'social security', 'social'],
        PIIType.CREDIT_CARD: ['card', 'credit', 'visa', 'mastercard', 'payment'],
        PIIType.BANK_ACCOUNT: ['account', 'bank', 'routing', 'iban'],
        PIIType.PASSWORD: ['password', 'pwd', 'pass', 'secret', 'key'],
        PIIType.API_KEY: ['api', 'key', 'token', 'secret', 'auth'],
    }
    
    @classmethod
    def get_patterns_for_type(cls, pii_type: PIIType) -> List[Pattern]:
        return cls.PATTERNS.get(pii_type, [])
    
    @classmethod
    def get_all_patterns(cls) -> Dict[PIIType, List[Pattern]]:
        return cls.PATTERNS
    
    @classmethod
    def has_context_keywords(cls, text: str, pii_type: PIIType) -> bool:
        keywords = cls.CONTEXT_KEYWORDS.get(pii_type, [])
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in keywords)


class BusinessSensitivePatterns:
    """Patterns for business-sensitive information"""
    
    PATTERNS = {
        'INTERNAL_EMAIL': [
            re.compile(r'\b[A-Za-z0-9._%+-]+@(?:company|internal|corp)\.com\b'),
        ],
        'EMPLOYEE_ID': [
            re.compile(r'\bEMP\d{4,8}\b'),
            re.compile(r'\b\d{6,8}\b'),
        ],
        'PROJECT_CODE': [
            re.compile(r'\b[A-Z]{2,4}-\d{4}\b'),
        ],
        'CONFIDENTIAL_MARKERS': [
            re.compile(r'\b(?:CONFIDENTIAL|RESTRICTED|PROPRIETARY|INTERNAL ONLY)\b', re.IGNORECASE),
        ],
    }
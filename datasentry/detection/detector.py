from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import RecognizerResult, OperatorConfig

from .patterns import PIIType, CustomPIIPatterns, BusinessSensitivePatterns


@dataclass
class PIIDetection:
    entity_type: str
    start: int
    end: int
    confidence: float
    text: str
    context: str = ""


@dataclass
class DetectionResult:
    original_text: str
    detected_entities: List[PIIDetection]
    risk_score: float
    has_high_risk_pii: bool
    detection_metadata: Dict[str, Any]


class PIIDetector:
    """Core PII detection engine using Presidio and custom patterns"""
    
    def __init__(self, enable_custom_patterns: bool = True, enable_ner_models: bool = True):
        self.enable_custom_patterns = enable_custom_patterns
        self.enable_ner_models = enable_ner_models
        
        # Initialize Presidio analyzer
        self._setup_presidio_analyzer()
        
        # Initialize custom pattern matcher
        self.custom_patterns = CustomPIIPatterns()
        self.business_patterns = BusinessSensitivePatterns()
    
    def _setup_presidio_analyzer(self):
        """Setup Presidio analyzer with NLP models"""
        try:
            if self.enable_ner_models:
                # Configure NLP engine (using spaCy)
                configuration = {
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
                }
                nlp_engine_provider = NlpEngineProvider(nlp_configuration=configuration)
                nlp_engine = nlp_engine_provider.create_engine()
                
                self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
            else:
                self.analyzer = AnalyzerEngine()
        except Exception as e:
            # Fallback to basic analyzer without advanced NLP
            self.analyzer = AnalyzerEngine()
    
    def detect_pii(self, text: str, language: str = "en") -> DetectionResult:
        """
        Detect PII in the given text using multiple detection methods
        
        Args:
            text: Input text to analyze
            language: Language code for NLP processing
            
        Returns:
            DetectionResult with detected PII entities and metadata
        """
        detected_entities = []
        detection_metadata = {}
        
        # 1. Use Presidio for standard PII detection
        if self.enable_ner_models:
            presidio_results = self._detect_with_presidio(text, language)
            detected_entities.extend(presidio_results)
            detection_metadata["presidio_entities"] = len(presidio_results)
        
        # 2. Use custom regex patterns
        if self.enable_custom_patterns:
            pattern_results = self._detect_with_patterns(text)
            detected_entities.extend(pattern_results)
            detection_metadata["pattern_entities"] = len(pattern_results)
        
        # 3. Business-sensitive pattern detection
        business_results = self._detect_business_sensitive(text)
        detected_entities.extend(business_results)
        detection_metadata["business_entities"] = len(business_results)
        
        # Remove duplicates and merge overlapping detections
        detected_entities = self._deduplicate_detections(detected_entities)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(detected_entities)
        has_high_risk_pii = self._has_high_risk_entities(detected_entities)
        
        detection_metadata.update({
            "total_entities": len(detected_entities),
            "risk_score": risk_score,
            "detection_methods_used": {
                "presidio": self.enable_ner_models,
                "custom_patterns": self.enable_custom_patterns,
                "business_patterns": True
            }
        })
        
        return DetectionResult(
            original_text=text,
            detected_entities=detected_entities,
            risk_score=risk_score,
            has_high_risk_pii=has_high_risk_pii,
            detection_metadata=detection_metadata
        )
    
    def _detect_with_presidio(self, text: str, language: str) -> List[PIIDetection]:
        """Detect PII using Presidio analyzer"""
        try:
            results = self.analyzer.analyze(text=text, language=language)
            detections = []
            
            for result in results:
                detection = PIIDetection(
                    entity_type=result.entity_type,
                    start=result.start,
                    end=result.end,
                    confidence=result.score,
                    text=text[result.start:result.end],
                    context=self._extract_context(text, result.start, result.end)
                )
                detections.append(detection)
            
            return detections
        except Exception as e:
            # Log error and return empty list
            return []
    
    def _detect_with_patterns(self, text: str) -> List[PIIDetection]:
        """Detect PII using custom regex patterns"""
        detections = []
        
        for pii_type, patterns in self.custom_patterns.get_all_patterns().items():
            for pattern in patterns:
                matches = pattern.finditer(text)
                for match in matches:
                    # Check for context keywords to improve accuracy
                    has_context = self.custom_patterns.has_context_keywords(text, pii_type)
                    confidence = 0.9 if has_context else 0.7
                    
                    detection = PIIDetection(
                        entity_type=pii_type.value,
                        start=match.start(),
                        end=match.end(),
                        confidence=confidence,
                        text=match.group(),
                        context=self._extract_context(text, match.start(), match.end())
                    )
                    detections.append(detection)
        
        return detections
    
    def _detect_business_sensitive(self, text: str) -> List[PIIDetection]:
        """Detect business-sensitive information"""
        detections = []
        
        for category, patterns in self.business_patterns.PATTERNS.items():
            for pattern in patterns:
                matches = pattern.finditer(text)
                for match in matches:
                    detection = PIIDetection(
                        entity_type=f"BUSINESS_{category}",
                        start=match.start(),
                        end=match.end(),
                        confidence=0.8,
                        text=match.group(),
                        context=self._extract_context(text, match.start(), match.end())
                    )
                    detections.append(detection)
        
        return detections
    
    def _extract_context(self, text: str, start: int, end: int, context_window: int = 50) -> str:
        """Extract surrounding context for a detected entity"""
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        return text[context_start:context_end]
    
    def _deduplicate_detections(self, detections: List[PIIDetection]) -> List[PIIDetection]:
        """Remove duplicate and overlapping detections"""
        if not detections:
            return []
        
        # Sort by start position
        sorted_detections = sorted(detections, key=lambda x: (x.start, x.end))
        merged = [sorted_detections[0]]
        
        for current in sorted_detections[1:]:
            last = merged[-1]
            
            # Check for overlap
            if current.start <= last.end:
                # Keep the detection with higher confidence
                if current.confidence > last.confidence:
                    merged[-1] = current
            else:
                merged.append(current)
        
        return merged
    
    def _calculate_risk_score(self, detections: List[PIIDetection]) -> float:
        """Calculate overall risk score based on detected entities"""
        if not detections:
            return 0.0
        
        high_risk_entities = {"US_SSN", "CREDIT_CARD", "AWS_ACCESS_KEY", "API_KEY", "PASSWORD"}
        medium_risk_entities = {"EMAIL", "PHONE_NUMBER", "PERSON", "BANK_ACCOUNT"}
        
        risk_score = 0.0
        
        for detection in detections:
            entity_weight = 1.0
            
            if detection.entity_type in high_risk_entities:
                entity_weight = 3.0
            elif detection.entity_type in medium_risk_entities:
                entity_weight = 2.0
            elif detection.entity_type.startswith("BUSINESS_"):
                entity_weight = 2.5
            
            risk_score += detection.confidence * entity_weight
        
        # Normalize to 0-1 scale
        max_possible_score = len(detections) * 3.0
        return min(1.0, risk_score / max_possible_score)
    
    def _has_high_risk_entities(self, detections: List[PIIDetection]) -> bool:
        """Check if any high-risk PII entities are detected"""
        high_risk_entities = {"US_SSN", "CREDIT_CARD", "AWS_ACCESS_KEY", "API_KEY", "PASSWORD"}
        return any(detection.entity_type in high_risk_entities for detection in detections)
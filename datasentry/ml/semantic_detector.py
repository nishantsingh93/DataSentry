import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import torch
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.cluster import DBSCAN
import structlog

from ..detection.detector import PIIDetection, DetectionResult
from ..detection.patterns import PIIType

logger = structlog.get_logger(__name__)


@dataclass
class SemanticMatch:
    text: str
    entity_type: str
    confidence: float
    semantic_similarity: float
    context_score: float


@dataclass
class ContextualFeatures:
    text: str
    embedding: np.ndarray
    surrounding_context: str
    context_embedding: np.ndarray
    position_ratio: float  # Position in text (0-1)
    sentence_context: str
    document_context: str


class SemanticPIIDetector:
    """Context-aware PII detection using semantic embeddings"""
    
    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        similarity_threshold: float = 0.7,
        context_window: int = 100
    ):
        self.model = SentenceTransformer(model_name)
        self.similarity_threshold = similarity_threshold
        self.context_window = context_window
        
        # Pre-computed embeddings for PII patterns
        self.pii_embeddings = {}
        self.context_patterns = {}
        self._initialize_semantic_patterns()
    
    def _initialize_semantic_patterns(self):
        """Initialize semantic patterns for different PII types"""
        pii_examples = {
            PIIType.EMAIL: [
                "email address", "electronic mail", "contact email",
                "send message to", "write to", "email me at"
            ],
            PIIType.PHONE: [
                "phone number", "telephone", "call me", "mobile number",
                "contact number", "reach me at", "dial"
            ],
            PIIType.PERSON: [
                "person name", "full name", "individual", "contact person",
                "employee", "customer", "user", "client"
            ],
            PIIType.SSN: [
                "social security", "SSN", "identification number",
                "government ID", "national identifier"
            ],
            PIIType.CREDIT_CARD: [
                "credit card", "payment card", "card number",
                "financial account", "payment method"
            ],
            PIIType.LOCATION: [
                "address", "location", "place", "residence",
                "home address", "business address", "street"
            ]
        }
        
        # Create embeddings for each PII type
        for pii_type, examples in pii_examples.items():
            embeddings = self.model.encode(examples)
            self.pii_embeddings[pii_type] = embeddings
        
        # Context patterns that indicate PII
        context_indicators = {
            "personal_info": [
                "personal information", "confidential data", "private details",
                "sensitive information", "personal data"
            ],
            "contact_info": [
                "contact information", "reach out", "get in touch",
                "contact details", "communication"
            ],
            "financial_info": [
                "financial information", "payment details", "billing",
                "account information", "financial data"
            ]
        }
        
        for category, examples in context_indicators.items():
            self.context_patterns[category] = self.model.encode(examples)
    
    def extract_contextual_features(
        self, 
        text: str, 
        candidate_spans: List[Tuple[int, int]]
    ) -> List[ContextualFeatures]:
        """Extract contextual features for candidate spans"""
        features = []
        sentences = self._split_into_sentences(text)
        text_embedding = self.model.encode([text])[0]
        
        for start, end in candidate_spans:
            candidate_text = text[start:end]
            
            # Extract surrounding context
            context_start = max(0, start - self.context_window)
            context_end = min(len(text), end + self.context_window)
            surrounding_context = text[context_start:context_end]
            
            # Find sentence context
            sentence_context = self._find_sentence_context(text, start, end, sentences)
            
            # Generate embeddings
            candidate_embedding = self.model.encode([candidate_text])[0]
            context_embedding = self.model.encode([surrounding_context])[0]
            
            features.append(ContextualFeatures(
                text=candidate_text,
                embedding=candidate_embedding,
                surrounding_context=surrounding_context,
                context_embedding=context_embedding,
                position_ratio=start / len(text),
                sentence_context=sentence_context,
                document_context=text
            ))
        
        return features
    
    def detect_semantic_pii(
        self, 
        text: str, 
        candidate_detections: List[PIIDetection]
    ) -> List[PIIDetection]:
        """Enhance PII detections with semantic analysis"""
        if not candidate_detections:
            return []
        
        # Extract candidate spans
        candidate_spans = [(d.start, d.end) for d in candidate_detections]
        contextual_features = self.extract_contextual_features(text, candidate_spans)
        
        enhanced_detections = []
        
        for detection, features in zip(candidate_detections, contextual_features):
            # Calculate semantic similarity scores
            semantic_scores = self._calculate_semantic_scores(
                features, detection.entity_type
            )
            
            # Calculate context relevance
            context_relevance = self._calculate_context_relevance(features)
            
            # Adjust confidence based on semantic analysis
            adjusted_confidence = self._adjust_confidence(
                detection.confidence,
                semantic_scores,
                context_relevance
            )
            
            # Create enhanced detection
            enhanced_detection = PIIDetection(
                entity_type=detection.entity_type,
                start=detection.start,
                end=detection.end,
                confidence=adjusted_confidence,
                text=detection.text,
                context=features.surrounding_context
            )
            
            enhanced_detections.append(enhanced_detection)
        
        return enhanced_detections
    
    def _calculate_semantic_scores(
        self, 
        features: ContextualFeatures, 
        entity_type: str
    ) -> Dict[str, float]:
        """Calculate semantic similarity scores"""
        scores = {}
        
        # Try to match entity_type to PIIType enum
        pii_type = None
        for pt in PIIType:
            if pt.value == entity_type:
                pii_type = pt
                break
        
        if pii_type and pii_type in self.pii_embeddings:
            # Calculate similarity to known PII patterns
            pii_patterns = self.pii_embeddings[pii_type]
            similarities = cosine_similarity(
                features.embedding.reshape(1, -1),
                pii_patterns
            )[0]
            scores['pattern_similarity'] = float(np.max(similarities))
        else:
            scores['pattern_similarity'] = 0.5  # Default for unknown types
        
        # Calculate context similarity
        max_context_sim = 0.0
        for category, pattern_embeddings in self.context_patterns.items():
            similarities = cosine_similarity(
                features.context_embedding.reshape(1, -1),
                pattern_embeddings
            )[0]
            max_context_sim = max(max_context_sim, np.max(similarities))
        
        scores['context_similarity'] = float(max_context_sim)
        
        return scores
    
    def _calculate_context_relevance(self, features: ContextualFeatures) -> float:
        """Calculate how relevant the context is for PII detection"""
        context_indicators = [
            "personal", "private", "confidential", "sensitive",
            "contact", "information", "details", "data"
        ]
        
        context_lower = features.surrounding_context.lower()
        relevance_score = sum(
            1 for indicator in context_indicators 
            if indicator in context_lower
        ) / len(context_indicators)
        
        return relevance_score
    
    def _adjust_confidence(
        self,
        original_confidence: float,
        semantic_scores: Dict[str, float],
        context_relevance: float
    ) -> float:
        """Adjust confidence based on semantic analysis"""
        # Weighted combination of factors
        pattern_weight = 0.4
        context_weight = 0.3
        relevance_weight = 0.3
        
        semantic_boost = (
            pattern_weight * semantic_scores.get('pattern_similarity', 0.5) +
            context_weight * semantic_scores.get('context_similarity', 0.5) +
            relevance_weight * context_relevance
        )
        
        # Adjust original confidence
        if semantic_boost > 0.6:
            # Boost confidence for strong semantic matches
            adjusted = original_confidence + (1 - original_confidence) * 0.2
        elif semantic_boost < 0.3:
            # Reduce confidence for weak semantic matches
            adjusted = original_confidence * 0.8
        else:
            # Minimal adjustment for moderate matches
            adjusted = original_confidence
        
        return min(1.0, max(0.0, adjusted))
    
    def _split_into_sentences(self, text: str) -> List[str]:
        """Simple sentence splitting"""
        import re
        sentences = re.split(r'[.!?]+', text)
        return [s.strip() for s in sentences if s.strip()]
    
    def _find_sentence_context(
        self, 
        text: str, 
        start: int, 
        end: int, 
        sentences: List[str]
    ) -> str:
        """Find the sentence containing the candidate span"""
        current_pos = 0
        for sentence in sentences:
            sentence_end = current_pos + len(sentence)
            if current_pos <= start <= sentence_end:
                return sentence
            current_pos = sentence_end + 1  # Account for delimiter
        
        return text[max(0, start-50):min(len(text), end+50)]


class ConfidenceCalibrator:
    """ML-based confidence calibration for PII detection"""
    
    def __init__(self):
        self.calibration_data = []
        self.is_trained = False
        self.feature_weights = {
            'pattern_match_score': 0.3,
            'context_score': 0.25,
            'position_score': 0.15,
            'length_score': 0.1,
            'surrounding_text_score': 0.2
        }
    
    def extract_calibration_features(
        self, 
        detection: PIIDetection, 
        full_text: str
    ) -> Dict[str, float]:
        """Extract features for confidence calibration"""
        features = {}
        
        # Pattern match strength
        features['pattern_match_score'] = detection.confidence
        
        # Context analysis
        context_lower = detection.context.lower()
        context_indicators = ['personal', 'private', 'contact', 'information']
        features['context_score'] = sum(
            1 for indicator in context_indicators if indicator in context_lower
        ) / len(context_indicators)
        
        # Position in text (beginning/middle/end)
        position_ratio = detection.start / len(full_text)
        if position_ratio < 0.1:
            features['position_score'] = 0.8  # Beginning is often important
        elif position_ratio > 0.9:
            features['position_score'] = 0.6  # End is moderately important
        else:
            features['position_score'] = 1.0  # Middle is most important
        
        # Length normalization
        text_length = len(detection.text)
        if text_length < 3:
            features['length_score'] = 0.3  # Very short, likely false positive
        elif text_length > 50:
            features['length_score'] = 0.7  # Very long, may be over-inclusive
        else:
            features['length_score'] = 1.0  # Good length
        
        # Surrounding text analysis
        surrounding_words = detection.context.split()
        suspicious_words = ['example', 'test', 'sample', 'fake', 'dummy']
        features['surrounding_text_score'] = 1.0 - (
            sum(1 for word in surrounding_words if word.lower() in suspicious_words) /
            max(1, len(surrounding_words))
        )
        
        return features
    
    def calibrate_confidence(
        self, 
        detection: PIIDetection, 
        full_text: str
    ) -> float:
        """Calibrate confidence score"""
        features = self.extract_calibration_features(detection, full_text)
        
        # Weighted combination of features
        calibrated_score = sum(
            features[feature] * weight
            for feature, weight in self.feature_weights.items()
        )
        
        # Apply sigmoid normalization
        calibrated_score = 1 / (1 + np.exp(-5 * (calibrated_score - 0.5)))
        
        return float(calibrated_score)
    
    def add_training_sample(
        self, 
        detection: PIIDetection, 
        full_text: str, 
        is_true_positive: bool
    ):
        """Add training sample for calibration"""
        features = self.extract_calibration_features(detection, full_text)
        self.calibration_data.append({
            'features': features,
            'label': 1.0 if is_true_positive else 0.0
        })
    
    def train_calibrator(self):
        """Train confidence calibrator (placeholder for ML training)"""
        if len(self.calibration_data) < 10:
            logger.warning("Insufficient training data for calibration")
            return
        
        # In a real implementation, you would train an ML model here
        # For now, we'll just update feature weights based on simple heuristics
        true_positives = [d for d in self.calibration_data if d['label'] == 1.0]
        false_positives = [d for d in self.calibration_data if d['label'] == 0.0]
        
        if true_positives and false_positives:
            # Simple feature importance based on differences
            for feature in self.feature_weights:
                tp_avg = np.mean([d['features'][feature] for d in true_positives])
                fp_avg = np.mean([d['features'][feature] for d in false_positives])
                
                # Increase weight if feature discriminates well
                discrimination = abs(tp_avg - fp_avg)
                self.feature_weights[feature] *= (1 + discrimination * 0.1)
            
            # Normalize weights
            total_weight = sum(self.feature_weights.values())
            for feature in self.feature_weights:
                self.feature_weights[feature] /= total_weight
        
        self.is_trained = True
        logger.info("Confidence calibrator trained", samples=len(self.calibration_data))


class CustomNERTrainer:
    """Training custom NER models for domain-specific PII"""
    
    def __init__(self):
        self.training_data = []
        self.model = None
        
    def add_training_example(
        self, 
        text: str, 
        entities: List[Dict[str, Any]]
    ):
        """Add training example"""
        self.training_data.append({
            'text': text,
            'entities': entities
        })
    
    def prepare_training_data(self) -> List[Tuple[str, Dict]]:
        """Prepare training data in spaCy format"""
        training_examples = []
        
        for example in self.training_data:
            text = example['text']
            entities = []
            
            for entity in example['entities']:
                entities.append((
                    entity['start'],
                    entity['end'],
                    entity['label']
                ))
            
            training_examples.append((text, {'entities': entities}))
        
        return training_examples
    
    def train_custom_model(self, model_output_path: str):
        """Train custom NER model (simplified implementation)"""
        if len(self.training_data) < 50:
            logger.warning("Insufficient training data for custom NER model")
            return
        
        try:
            import spacy
            from spacy.training import Example
            
            # Load base model
            nlp = spacy.load("en_core_web_sm")
            
            # Add custom entity recognizer
            if "ner" not in nlp.pipe_names:
                ner = nlp.add_pipe("ner")
            else:
                ner = nlp.get_pipe("ner")
            
            # Add custom labels
            custom_labels = set()
            for example in self.training_data:
                for entity in example['entities']:
                    custom_labels.add(entity['label'])
            
            for label in custom_labels:
                ner.add_label(label)
            
            # Prepare training examples
            training_examples = []
            for text, annotations in self.prepare_training_data():
                doc = nlp.make_doc(text)
                example = Example.from_dict(doc, annotations)
                training_examples.append(example)
            
            # Train model (simplified)
            nlp.update(training_examples)
            
            # Save model
            nlp.to_disk(model_output_path)
            
            logger.info(
                "Custom NER model trained and saved",
                output_path=model_output_path,
                training_examples=len(training_examples),
                custom_labels=list(custom_labels)
            )
            
        except Exception as e:
            logger.error("Failed to train custom NER model", error=str(e))
    
    def load_trained_model(self, model_path: str):
        """Load trained custom model"""
        try:
            import spacy
            self.model = spacy.load(model_path)
            logger.info("Custom NER model loaded", model_path=model_path)
        except Exception as e:
            logger.error("Failed to load custom NER model", error=str(e))
    
    def predict(self, text: str) -> List[Dict[str, Any]]:
        """Predict with custom model"""
        if not self.model:
            return []
        
        doc = self.model(text)
        entities = []
        
        for ent in doc.ents:
            entities.append({
                'text': ent.text,
                'label': ent.label_,
                'start': ent.start_char,
                'end': ent.end_char,
                'confidence': ent._.confidence if hasattr(ent._, 'confidence') else 0.8
            })
        
        return entities
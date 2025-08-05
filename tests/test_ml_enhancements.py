import pytest
import numpy as np
from unittest.mock import Mock, patch, MagicMock
from datasentry.ml.semantic_detector import (
    SemanticPIIDetector, ConfidenceCalibrator, CustomNERTrainer,
    ContextualFeatures, SemanticMatch
)
from datasentry.detection.detector import PIIDetection
from datasentry.detection.patterns import PIIType


class TestSemanticPIIDetector:
    
    @pytest.fixture
    def semantic_detector(self):
        # Mock the SentenceTransformer to avoid downloading models in tests
        with patch('datasentry.ml.semantic_detector.SentenceTransformer') as mock_st:
            mock_model = Mock()
            mock_model.encode.return_value = np.random.rand(5, 384)  # Mock embeddings
            mock_st.return_value = mock_model
            
            detector = SemanticPIIDetector()
            detector.model = mock_model
            return detector
    
    @pytest.fixture
    def sample_detections(self):
        return [
            PIIDetection(
                entity_type="EMAIL",
                start=15,
                end=30,
                confidence=0.8,
                text="john@example.com",
                context="Please contact john@example.com for more information"
            ),
            PIIDetection(
                entity_type="PHONE_NUMBER",
                start=40,
                end=54,
                confidence=0.7,
                text="(555) 123-4567",
                context="or call me at (555) 123-4567 during business hours"
            )
        ]
    
    def test_initialization(self, semantic_detector):
        """Test semantic detector initialization"""
        assert semantic_detector.similarity_threshold == 0.7
        assert semantic_detector.context_window == 100
        assert len(semantic_detector.pii_embeddings) > 0
        assert len(semantic_detector.context_patterns) > 0
    
    def test_extract_contextual_features(self, semantic_detector):
        """Test contextual feature extraction"""
        text = "Please contact me at john@example.com or call (555) 123-4567 for urgent matters."
        candidate_spans = [(21, 36), (49, 63)]  # email and phone positions
        
        features = semantic_detector.extract_contextual_features(text, candidate_spans)
        
        assert len(features) == 2
        for feature in features:
            assert isinstance(feature, ContextualFeatures)
            assert hasattr(feature, 'text')
            assert hasattr(feature, 'embedding')
            assert hasattr(feature, 'context_embedding')
            assert 0 <= feature.position_ratio <= 1
    
    def test_detect_semantic_pii(self, semantic_detector, sample_detections):
        """Test semantic PII detection enhancement"""
        text = "Please contact john@example.com or call (555) 123-4567"
        
        enhanced_detections = semantic_detector.detect_semantic_pii(text, sample_detections)
        
        assert len(enhanced_detections) == len(sample_detections)
        for detection in enhanced_detections:
            assert isinstance(detection, PIIDetection)
            assert 0 <= detection.confidence <= 1
    
    def test_semantic_similarity_calculation(self, semantic_detector):
        """Test semantic similarity scoring"""
        # Create mock contextual features
        features = ContextualFeatures(
            text="john@example.com",
            embedding=np.random.rand(384),
            surrounding_context="contact john@example.com for info",
            context_embedding=np.random.rand(384),
            position_ratio=0.5,
            sentence_context="Please contact john@example.com",
            document_context="Full document text here"
        )
        
        scores = semantic_detector._calculate_semantic_scores(features, "EMAIL")
        
        assert "pattern_similarity" in scores
        assert "context_similarity" in scores
        assert 0 <= scores["pattern_similarity"] <= 1
        assert 0 <= scores["context_similarity"] <= 1
    
    def test_context_relevance_calculation(self, semantic_detector):
        """Test context relevance scoring"""
        # High relevance context
        high_relevance_features = ContextualFeatures(
            text="test@example.com",
            embedding=np.random.rand(384),
            surrounding_context="personal email information confidential contact details",
            context_embedding=np.random.rand(384),
            position_ratio=0.3,
            sentence_context="Personal email",
            document_context="Document"
        )
        
        high_score = semantic_detector._calculate_context_relevance(high_relevance_features)
        
        # Low relevance context
        low_relevance_features = ContextualFeatures(
            text="test@example.com",
            embedding=np.random.rand(384),
            surrounding_context="the weather is nice today",
            context_embedding=np.random.rand(384),
            position_ratio=0.3,
            sentence_context="Weather email",
            document_context="Document"
        )
        
        low_score = semantic_detector._calculate_context_relevance(low_relevance_features)
        
        assert high_score > low_score
        assert 0 <= high_score <= 1
        assert 0 <= low_score <= 1
    
    def test_confidence_adjustment(self, semantic_detector):
        """Test confidence score adjustment"""
        # High semantic similarity should boost confidence
        high_semantic_scores = {"pattern_similarity": 0.9, "context_similarity": 0.8}
        high_context_relevance = 0.8
        
        boosted_confidence = semantic_detector._adjust_confidence(
            0.6, high_semantic_scores, high_context_relevance
        )
        
        # Low semantic similarity should reduce confidence
        low_semantic_scores = {"pattern_similarity": 0.2, "context_similarity": 0.1}
        low_context_relevance = 0.1
        
        reduced_confidence = semantic_detector._adjust_confidence(
            0.6, low_semantic_scores, low_context_relevance
        )
        
        assert boosted_confidence > 0.6
        assert reduced_confidence < 0.6
        assert 0 <= boosted_confidence <= 1
        assert 0 <= reduced_confidence <= 1
    
    def test_sentence_splitting(self, semantic_detector):
        """Test sentence splitting functionality"""
        text = "First sentence. Second sentence! Third sentence? Fourth sentence."
        sentences = semantic_detector._split_into_sentences(text)
        
        assert len(sentences) == 4
        assert "First sentence" in sentences[0]
        assert "Second sentence" in sentences[1]
    
    def test_find_sentence_context(self, semantic_detector):
        """Test finding sentence context for spans"""
        text = "First sentence with email@test.com here. Second sentence follows."
        sentences = semantic_detector._split_into_sentences(text)
        
        # Email is in first sentence
        context = semantic_detector._find_sentence_context(text, 20, 35, sentences)
        
        assert "First sentence" in context
        assert "email@test.com" in context


class TestConfidenceCalibrator:
    
    @pytest.fixture
    def calibrator(self):
        return ConfidenceCalibrator()
    
    @pytest.fixture
    def sample_detection(self):
        return PIIDetection(
            entity_type="EMAIL",
            start=10,
            end=25,
            confidence=0.8,
            text="test@example.com",
            context="Please contact test@example.com for more information"
        )
    
    def test_extract_calibration_features(self, calibrator, sample_detection):
        """Test feature extraction for calibration"""
        full_text = "Please contact test@example.com for more information about our services"
        
        features = calibrator.extract_calibration_features(sample_detection, full_text)
        
        expected_features = [
            'pattern_match_score', 'context_score', 'position_score',
            'length_score', 'surrounding_text_score'
        ]
        
        for feature in expected_features:
            assert feature in features
            assert 0 <= features[feature] <= 1
    
    def test_calibrate_confidence(self, calibrator, sample_detection):
        """Test confidence calibration"""
        full_text = "Please contact test@example.com for information"
        
        calibrated_score = calibrator.calibrate_confidence(sample_detection, full_text)
        
        assert 0 <= calibrated_score <= 1
        assert isinstance(calibrated_score, float)
    
    def test_add_training_sample(self, calibrator, sample_detection):
        """Test adding training samples"""
        full_text = "Contact test@example.com"
        
        initial_count = len(calibrator.calibration_data)
        
        calibrator.add_training_sample(sample_detection, full_text, True)
        calibrator.add_training_sample(sample_detection, full_text, False)
        
        assert len(calibrator.calibration_data) == initial_count + 2
        assert calibrator.calibration_data[-2]["label"] == 1.0
        assert calibrator.calibration_data[-1]["label"] == 0.0
    
    def test_train_calibrator(self, calibrator, sample_detection):
        """Test calibrator training"""
        full_text = "Contact test@example.com"
        
        # Add training samples
        for i in range(15):
            is_positive = i % 2 == 0
            calibrator.add_training_sample(sample_detection, full_text, is_positive)
        
        initial_weights = calibrator.feature_weights.copy()
        
        calibrator.train_calibrator()
        
        assert calibrator.is_trained
        # Weights should be normalized
        assert abs(sum(calibrator.feature_weights.values()) - 1.0) < 0.01
    
    def test_insufficient_training_data(self, calibrator):
        """Test training with insufficient data"""
        # Add only a few samples
        sample_detection = PIIDetection("EMAIL", 0, 10, 0.8, "test@example.com", "context")
        
        for i in range(5):  # Less than minimum required
            calibrator.add_training_sample(sample_detection, "text", True)
        
        calibrator.train_calibrator()
        
        # Should handle gracefully but not be trained
        assert not calibrator.is_trained
    
    def test_feature_scoring_logic(self, calibrator):
        """Test specific feature scoring logic"""
        # Test position scoring
        beginning_detection = PIIDetection("EMAIL", 5, 20, 0.8, "test@example.com", "context")
        middle_detection = PIIDetection("EMAIL", 50, 65, 0.8, "test@example.com", "context")
        end_detection = PIIDetection("EMAIL", 90, 105, 0.8, "test@example.com", "context")
        
        full_text = "A" * 110  # 110 character text
        
        beginning_features = calibrator.extract_calibration_features(beginning_detection, full_text)
        middle_features = calibrator.extract_calibration_features(middle_detection, full_text)
        end_features = calibrator.extract_calibration_features(end_detection, full_text)
        
        # Middle position should have highest score
        assert middle_features['position_score'] >= beginning_features['position_score']
        assert middle_features['position_score'] >= end_features['position_score']
        
        # Test length scoring
        short_detection = PIIDetection("EMAIL", 0, 2, 0.8, "ab", "context")
        normal_detection = PIIDetection("EMAIL", 0, 15, 0.8, "test@example.com", "context")
        long_detection = PIIDetection("EMAIL", 0, 60, 0.8, "very_long_email_address_that_exceeds_normal_length@example.com", "context")
        
        short_features = calibrator.extract_calibration_features(short_detection, full_text)
        normal_features = calibrator.extract_calibration_features(normal_detection, full_text)
        long_features = calibrator.extract_calibration_features(long_detection, full_text)
        
        # Normal length should have highest score
        assert normal_features['length_score'] > short_features['length_score']
        assert normal_features['length_score'] > long_features['length_score']


class TestCustomNERTrainer:
    
    @pytest.fixture
    def ner_trainer(self):
        return CustomNERTrainer()
    
    def test_add_training_example(self, ner_trainer):
        """Test adding training examples"""
        text = "John Smith works at Company Inc and can be reached at john@company.com"
        entities = [
            {"start": 0, "end": 10, "label": "PERSON"},
            {"start": 20, "end": 31, "label": "ORGANIZATION"},
            {"start": 54, "end": 71, "label": "EMAIL"}
        ]
        
        initial_count = len(ner_trainer.training_data)
        ner_trainer.add_training_example(text, entities)
        
        assert len(ner_trainer.training_data) == initial_count + 1
        assert ner_trainer.training_data[-1]["text"] == text
        assert ner_trainer.training_data[-1]["entities"] == entities
    
    def test_prepare_training_data(self, ner_trainer):
        """Test preparation of training data for spaCy"""
        ner_trainer.add_training_example(
            "Contact John at john@example.com",
            [
                {"start": 8, "end": 12, "label": "PERSON"},
                {"start": 16, "end": 33, "label": "EMAIL"}
            ]
        )
        
        training_examples = ner_trainer.prepare_training_data()
        
        assert len(training_examples) == 1
        text, annotations = training_examples[0]
        assert text == "Contact John at john@example.com"
        assert "entities" in annotations
        assert len(annotations["entities"]) == 2
        
        # Check entity format
        person_entity = annotations["entities"][0]
        assert person_entity == (8, 12, "PERSON")
    
    @patch('datasentry.ml.semantic_detector.spacy')
    def test_train_custom_model(self, mock_spacy, ner_trainer):
        """Test custom model training"""
        # Mock spaCy components
        mock_nlp = Mock()
        mock_ner = Mock()
        mock_doc = Mock()
        mock_example = Mock()
        
        mock_spacy.load.return_value = mock_nlp
        mock_nlp.pipe_names = ["ner"]
        mock_nlp.get_pipe.return_value = mock_ner
        mock_nlp.make_doc.return_value = mock_doc
        
        # Mock Example class
        with patch('datasentry.ml.semantic_detector.Example') as mock_example_class:
            mock_example_class.from_dict.return_value = mock_example
            
            # Add sufficient training data
            for i in range(60):
                ner_trainer.add_training_example(
                    f"Person{i} at email{i}@example.com",
                    [
                        {"start": 0, "end": 7, "label": "PERSON"},
                        {"start": 11, "end": 30, "label": "EMAIL"}
                    ]
                )
            
            # Train model
            ner_trainer.train_custom_model("/tmp/test_model")
            
            # Verify spaCy interactions
            mock_spacy.load.assert_called_once_with("en_core_web_sm")
            mock_ner.add_label.assert_called()
            mock_nlp.update.assert_called_once()
            mock_nlp.to_disk.assert_called_once_with("/tmp/test_model")
    
    def test_insufficient_training_data(self, ner_trainer):
        """Test training with insufficient data"""
        # Add only a few examples
        for i in range(10):  # Less than minimum required (50)
            ner_trainer.add_training_example(
                f"Text {i}",
                [{"start": 0, "end": 4, "label": "TEST"}]
            )
        
        # Should handle gracefully
        ner_trainer.train_custom_model("/tmp/test_model")
        # No exception should be raised
    
    @patch('datasentry.ml.semantic_detector.spacy')
    def test_load_trained_model(self, mock_spacy, ner_trainer):
        """Test loading trained model"""
        mock_model = Mock()
        mock_spacy.load.return_value = mock_model
        
        ner_trainer.load_trained_model("/path/to/model")
        
        assert ner_trainer.model == mock_model
        mock_spacy.load.assert_called_once_with("/path/to/model")
    
    def test_predict_with_custom_model(self, ner_trainer):
        """Test prediction with custom model"""
        # Mock the loaded model
        mock_model = Mock()
        mock_doc = Mock()
        mock_ent1 = Mock()
        mock_ent2 = Mock()
        
        # Configure mock entities
        mock_ent1.text = "John Smith"
        mock_ent1.label_ = "PERSON"
        mock_ent1.start_char = 0
        mock_ent1.end_char = 10
        
        mock_ent2.text = "john@example.com"
        mock_ent2.label_ = "EMAIL"
        mock_ent2.start_char = 20
        mock_ent2.end_char = 36
        
        mock_doc.ents = [mock_ent1, mock_ent2]
        mock_model.return_value = mock_doc
        
        ner_trainer.model = mock_model
        
        # Make prediction
        text = "John Smith works at john@example.com"
        entities = ner_trainer.predict(text)
        
        assert len(entities) == 2
        assert entities[0]["text"] == "John Smith"
        assert entities[0]["label"] == "PERSON"
        assert entities[1]["text"] == "john@example.com"
        assert entities[1]["label"] == "EMAIL"
    
    def test_predict_without_model(self, ner_trainer):
        """Test prediction without loaded model"""
        # Should return empty list if no model loaded
        entities = ner_trainer.predict("Some text")
        assert entities == []


class TestIntegrationScenarios:
    
    @pytest.fixture
    def integrated_system(self):
        """Create integrated system with mocked components"""
        with patch('datasentry.ml.semantic_detector.SentenceTransformer') as mock_st:
            mock_model = Mock()
            mock_model.encode.return_value = np.random.rand(5, 384)
            mock_st.return_value = mock_model
            
            semantic_detector = SemanticPIIDetector()
            semantic_detector.model = mock_model
            
            confidence_calibrator = ConfidenceCalibrator()
            
            return {
                "semantic_detector": semantic_detector,
                "confidence_calibrator": confidence_calibrator
            }
    
    def test_end_to_end_enhancement(self, integrated_system):
        """Test end-to-end PII detection enhancement"""
        semantic_detector = integrated_system["semantic_detector"]
        calibrator = integrated_system["confidence_calibrator"]
        
        # Initial detections from regular detector
        initial_detections = [
            PIIDetection(
                entity_type="EMAIL",
                start=10,
                end=25,
                confidence=0.75,
                text="user@example.com",
                context="Contact user@example.com for support"
            )
        ]
        
        text = "Contact user@example.com for support"
        
        # Enhance with semantic analysis
        enhanced_detections = semantic_detector.detect_semantic_pii(text, initial_detections)
        
        # Further calibrate confidence
        final_detections = []
        for detection in enhanced_detections:
            calibrated_confidence = calibrator.calibrate_confidence(detection, text)
            detection.confidence = calibrated_confidence
            final_detections.append(detection)
        
        assert len(final_detections) == 1
        assert 0 <= final_detections[0].confidence <= 1
    
    def test_batch_processing_with_ml_enhancements(self, integrated_system):
        """Test batch processing with ML enhancements"""
        semantic_detector = integrated_system["semantic_detector"]
        
        texts_and_detections = [
            ("Email me at work@company.com", [
                PIIDetection("EMAIL", 12, 28, 0.8, "work@company.com", "Email me at work@company.com")
            ]),
            ("Call (555) 123-4567 anytime", [
                PIIDetection("PHONE_NUMBER", 5, 19, 0.7, "(555) 123-4567", "Call (555) 123-4567 anytime")
            ])
        ]
        
        all_enhanced = []
        for text, detections in texts_and_detections:
            enhanced = semantic_detector.detect_semantic_pii(text, detections)
            all_enhanced.extend(enhanced)
        
        assert len(all_enhanced) == 2
        for detection in all_enhanced:
            assert isinstance(detection, PIIDetection)
            assert 0 <= detection.confidence <= 1
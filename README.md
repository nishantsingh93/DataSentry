# DataSentry: PII Guardrail Tool for AI Agent Interactions

DataSentry is a comprehensive solution for detecting, masking, and preventing Personally Identifiable Information (PII) from being inadvertently sent to external AI services. It acts as a security guardrail between your applications and AI APIs, ensuring compliance with privacy regulations and protecting sensitive data.

## 🔒 Key Features

- **Real-time PII Detection**: Advanced detection using Presidio, custom regex patterns, and NER models
- **Flexible Masking Options**: Full, partial, synthetic, hash-based, and redaction masking
- **Policy Enforcement**: Configurable rules with role-based access controls
- **AI Service Proxy**: Transparent interception of requests to OpenAI, Anthropic, Google, and other AI APIs
- **Comprehensive Auditing**: Structured logging with Elasticsearch integration
- **REST API**: Full-featured API for integration with existing systems
- **CLI Tools**: Command-line utilities for testing and administration
- **Compliance Reporting**: Built-in reports for regulatory compliance

## 🚀 Quick Start

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/your-org/DataSentry.git
cd DataSentry
```

2. **Run the setup script:**
```bash
python setup.py
```

This will:
- Install Python dependencies
- Download required spaCy models
- Create necessary directories
- Set up configuration files

3. **Configure environment:**
```bash
cp .env.example .env
# Edit .env with your settings
```

### Basic Usage

#### Start the API Server
```bash
python -m datasentry.cli serve --host 0.0.0.0 --port 8000
```

#### Test PII Detection
```bash
# Via CLI
echo "My email is john.doe@example.com" | python -m datasentry.cli detect

# Via API
curl -X POST "http://localhost:8000/api/v1/detect" \
  -H "Content-Type: application/json" \
  -d '{"text": "My SSN is 123-45-6789"}'
```

#### Mask PII in Text
```bash
# Via CLI
echo "Call me at (555) 123-4567" | python -m datasentry.cli mask --mask-type partial

# Via API
curl -X POST "http://localhost:8000/api/v1/mask" \
  -H "Content-Type: application/json" \
  -d '{"text": "My credit card is 4532-1234-5678-9012", "detect_first": true}'
```

## 📚 API Documentation

Once the server is running, visit:
- **Interactive API Docs**: http://localhost:8000/docs
- **ReDoc Documentation**: http://localhost:8000/redoc

### Core Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/detect` | POST | Detect PII in text |
| `/api/v1/mask` | POST | Mask PII in text |
| `/api/v1/sanitize` | POST | Apply policy-based sanitization |
| `/api/v1/proxy` | POST | Proxy requests to AI services |
| `/api/v1/health` | GET | Health check |
| `/api/v1/policies` | GET/PUT | Manage policies |

## 🔧 Configuration

### Environment Variables

Key configuration options in `.env`:

```bash
# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
SECRET_KEY=your-secret-key-here
ADMIN_API_KEY=your-admin-api-key-here

# Detection Configuration
PII_DETECTION_THRESHOLD=0.8
ENABLE_CUSTOM_PATTERNS=true
ENABLE_NER_MODELS=true

# Logging Configuration
LOG_LEVEL=INFO
ELASTICSEARCH_URL=http://localhost:9200
ELASTICSEARCH_INDEX=datasentry-logs

# AI Provider Keys (for proxy functionality)
OPENAI_API_KEY=your-openai-key
ANTHROPIC_API_KEY=your-anthropic-key
```

### Policy Configuration

Edit `config/policies.yaml` to customize PII handling policies:

```yaml
default_policy:
  action: "mask"
  confidence_threshold: 0.8

entity_policies:
  EMAIL:
    action: "mask"
    confidence_threshold: 0.9
    mask_type: "partial"
  
  US_SSN:
    action: "block"
    confidence_threshold: 0.7
  
  CREDIT_CARD:
    action: "block"
    confidence_threshold: 0.8

role_overrides:
  admin:
    can_override: true
    bypass_entities: ["PERSON", "LOCATION"]
```

## 🎯 Use Cases

### 1. AI Agent Proxy

Intercept and sanitize requests to AI services:

```python
import requests

# Instead of calling AI service directly:
# response = requests.post("https://api.openai.com/v1/chat/completions", ...)

# Route through DataSentry proxy:
response = requests.post("http://localhost:8000/api/v1/proxy", json={
    "target_url": "https://api.openai.com/v1/chat/completions",
    "payload": {
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "user", "content": "My SSN is 123-45-6789, help me with taxes"}]
    },
    "sanitize_request": True,
    "policy_name": "default"
}, headers={"X-API-Key": "your-admin-key"})
```

### 2. Text Sanitization Pipeline

```python
from datasentry.detection.detector import PIIDetector
from datasentry.masking.anonymizer import PIIMasker
from datasentry.policies.engine import PolicyEngine

detector = PIIDetector()
masker = PIIMasker()
policy_engine = PolicyEngine()

text = "Contact John at john@example.com or call (555) 123-4567"

# Detect PII
detection_result = detector.detect_pii(text)

# Apply policy
policy_decision = policy_engine.evaluate_policy(detection_result)

if policy_decision.action == "mask":
    masking_result = masker.mask_pii(detection_result, policy_decision.masking_config)
    sanitized_text = masking_result.masked_text
elif policy_decision.action == "block":
    raise Exception("Content blocked due to PII")
```

### 3. Compliance Monitoring

```bash
# Generate PII detection report
python -m datasentry.cli report \
  --start-date 2024-01-01 \
  --end-date 2024-01-31 \
  --report-type detections \
  --output compliance_report.json
```

## 🧪 Testing

Run the test suite:

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run all tests
pytest

# Run specific test file
pytest tests/test_detection.py

# Run with coverage
pytest --cov=datasentry tests/
```

## 🔍 Supported PII Types

DataSentry can detect and handle the following PII types:

- **Contact Information**: Email addresses, phone numbers
- **Government IDs**: Social Security Numbers, passport numbers, driver's licenses
- **Financial**: Credit card numbers, bank account numbers
- **Technical**: IP addresses, AWS access keys, API keys, passwords
- **Personal**: Person names, locations, organizations
- **Business Sensitive**: Internal emails, employee IDs, project codes

## 📊 Monitoring & Observability

### Audit Logging

All PII detection and handling events are logged with structured data:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "event_type": "detection",
  "event_id": "uuid-here",
  "details": {
    "entities_detected": 2,
    "risk_score": 0.85,
    "processing_time_ms": 45.2
  }
}
```

### Elasticsearch Integration

If configured, logs are automatically sent to Elasticsearch for analysis and dashboards.

### Compliance Reports

Generate reports for:
- PII detection statistics
- Blocked requests
- Policy violations
- User activity

## 🛠️ Development

### Project Structure

```
DataSentry/
├── datasentry/
│   ├── api/           # FastAPI application
│   ├── detection/     # PII detection engine
│   ├── masking/       # PII masking/anonymization
│   ├── policies/      # Policy enforcement
│   ├── proxy/         # AI service proxy
│   ├── logging/       # Audit logging
│   └── core/          # Configuration and utilities
├── tests/             # Test suite
├── config/            # Configuration files
├── docs/              # Documentation
└── requirements.txt   # Dependencies
```

### Adding New PII Patterns

1. Edit `datasentry/detection/patterns.py`
2. Add new regex patterns to `CustomPIIPatterns.PATTERNS`
3. Update policy configuration in `config/policies.yaml`
4. Add tests in `tests/test_detection.py`

### Extending Masking Methods

1. Implement new masking logic in `datasentry/masking/anonymizer.py`
2. Update `MaskingType` enum
3. Add configuration options
4. Write tests

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and add tests
4. Run the test suite: `pytest`
5. Commit your changes: `git commit -m 'Add amazing feature'`
6. Push to the branch: `git push origin feature/amazing-feature`
7. Open a Pull Request

## 📋 Roadmap

- [ ] **Dashboard Interface**: Web-based management interface
- [ ] **IDE Plugins**: VSCode and IntelliJ extensions
- [ ] **SDK Libraries**: Python, JavaScript, and Go client libraries
- [ ] **Advanced ML Models**: Custom NER models for domain-specific PII
- [ ] **Vector Database Integration**: Context-aware PII detection
- [ ] **Cloud Provider Integrations**: AWS Macie, Google DLP API
- [ ] **Kubernetes Deployment**: Helm charts and operators

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: Check the `/docs` endpoint when running the API
- **Issues**: Report bugs on [GitHub Issues](https://github.com/your-org/DataSentry/issues)
- **Discussions**: Join our [GitHub Discussions](https://github.com/your-org/DataSentry/discussions)

## ⚖️ Legal & Compliance

DataSentry is designed to help with GDPR, CCPA, HIPAA, and other privacy regulation compliance, but **you are responsible for ensuring your use meets all applicable legal requirements**. This tool provides technical capabilities but does not constitute legal advice.

## 🙏 Acknowledgments

- [Microsoft Presidio](https://github.com/microsoft/presidio) for PII detection framework
- [spaCy](https://spacy.io/) for natural language processing
- [FastAPI](https://fastapi.tiangolo.com/) for the web framework
- The open-source community for inspiration and feedback

---

**DataSentry** - Protecting privacy in the age of AI 🛡️
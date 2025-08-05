import yaml
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from pathlib import Path

from ..detection.detector import DetectionResult


@dataclass
class PolicyDecision:
    action: str  # block, warn, mask, allow
    confidence_threshold: float
    masking_config: Dict[str, Any]
    bypass_allowed: bool
    reasons: List[str]


class PolicyEngine:
    """Policy enforcement engine for PII detection and handling"""
    
    def __init__(self, config_path: str = "./config/policies.yaml"):
        self.config_path = Path(config_path)
        self.policies = {}
        self.load_policies()
    
    def load_policies(self):
        """Load policies from YAML configuration file"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as file:
                    self.policies = yaml.safe_load(file)
            else:
                # Use default policies if config file doesn't exist
                self.policies = self._get_default_policies()
                self._save_default_config()
        except Exception as e:
            print(f"Error loading policies: {e}")
            self.policies = self._get_default_policies()
    
    def _get_default_policies(self) -> Dict[str, Any]:
        """Get default policy configuration"""
        return {
            "default_policy": {
                "action": "mask",
                "confidence_threshold": 0.8,
            },
            "entity_policies": {
                "EMAIL": {
                    "action": "mask",
                    "confidence_threshold": 0.9,
                    "mask_type": "partial"
                },
                "PHONE_NUMBER": {
                    "action": "mask",
                    "confidence_threshold": 0.8,
                    "mask_type": "partial"
                },
                "US_SSN": {
                    "action": "block",
                    "confidence_threshold": 0.7
                },
                "CREDIT_CARD": {
                    "action": "block",
                    "confidence_threshold": 0.8
                },
                "PERSON": {
                    "action": "warn",
                    "confidence_threshold": 0.8
                },
                "LOCATION": {
                    "action": "warn",
                    "confidence_threshold": 0.7
                },
                "IP_ADDRESS": {
                    "action": "mask",
                    "confidence_threshold": 0.9,
                    "mask_type": "full"
                },
                "AWS_ACCESS_KEY": {
                    "action": "block",
                    "confidence_threshold": 0.9
                },
                "API_KEY": {
                    "action": "block",
                    "confidence_threshold": 0.9
                },
                "PASSWORD": {
                    "action": "block",
                    "confidence_threshold": 0.8
                }
            },
            "role_overrides": {
                "admin": {
                    "can_override": True,
                    "bypass_entities": ["PERSON", "LOCATION"]
                },
                "developer": {
                    "can_override": False,
                    "bypass_entities": []
                },
                "analyst": {
                    "can_override": True,
                    "bypass_entities": ["LOCATION"]
                }
            },
            "business_rules": {
                "max_pii_entities_per_request": 5,
                "max_confidence_score_threshold": 0.95,
                "require_approval_for_high_risk": True,
                "log_all_detections": True
            }
        }
    
    def _save_default_config(self):
        """Save default configuration to file"""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, 'w') as file:
                yaml.dump(self.policies, file, default_flow_style=False, indent=2)
        except Exception as e:
            print(f"Error saving default config: {e}")
    
    def evaluate_policy(
        self,
        detection_result: DetectionResult,
        policy_name: str = "default",
        user_role: str = "user",
        bypass_high_risk: bool = False
    ) -> PolicyDecision:
        """
        Evaluate policy for detected PII entities
        
        Args:
            detection_result: PII detection results
            policy_name: Policy configuration to use
            user_role: User role for permission checks
            bypass_high_risk: Whether user can bypass high-risk blocks
            
        Returns:
            PolicyDecision with action to take
        """
        if not detection_result.detected_entities:
            return PolicyDecision(
                action="allow",
                confidence_threshold=0.0,
                masking_config={},
                bypass_allowed=True,
                reasons=["No PII detected"]
            )
        
        # Check business rules first
        business_rules = self.policies.get("business_rules", {})
        max_entities = business_rules.get("max_pii_entities_per_request", 5)
        max_confidence = business_rules.get("max_confidence_score_threshold", 0.95)
        
        reasons = []
        
        # Check if too many entities detected
        if len(detection_result.detected_entities) > max_entities:
            reasons.append(f"Too many PII entities detected: {len(detection_result.detected_entities)} > {max_entities}")
            return PolicyDecision(
                action="block",
                confidence_threshold=1.0,
                masking_config={},
                bypass_allowed=self._can_user_override(user_role),
                reasons=reasons
            )
        
        # Check if confidence too high
        max_entity_confidence = max([e.confidence for e in detection_result.detected_entities])
        if max_entity_confidence >= max_confidence:
            reasons.append(f"High confidence PII detected: {max_entity_confidence:.2f} >= {max_confidence}")
        
        # Determine action based on entity policies
        actions_by_priority = {"block": 4, "mask": 3, "warn": 2, "allow": 1}
        highest_action = "allow"
        highest_priority = 0
        masking_config = {}
        bypass_allowed = True
        
        entity_policies = self.policies.get("entity_policies", {})
        default_policy = self.policies.get("default_policy", {"action": "mask", "confidence_threshold": 0.8})
        
        for entity in detection_result.detected_entities:
            entity_policy = entity_policies.get(entity.entity_type, default_policy)
            confidence_threshold = entity_policy.get("confidence_threshold", 0.8)
            
            # Skip entity if confidence below threshold
            if entity.confidence < confidence_threshold:
                continue
            
            # Check if user can bypass this entity type
            if self._can_bypass_entity(user_role, entity.entity_type) and bypass_high_risk:
                continue
            
            action = entity_policy.get("action", "mask")
            priority = actions_by_priority.get(action, 1)
            
            if priority > highest_priority:
                highest_action = action
                highest_priority = priority
                bypass_allowed = self._can_user_override(user_role)
            
            # Build masking config
            if action == "mask":
                masking_config[entity.entity_type] = {
                    "mask_type": entity_policy.get("mask_type", "full"),
                    "mask_char": entity_policy.get("mask_char", "*"),
                    "confidence_threshold": confidence_threshold
                }
            
            reasons.append(f"{entity.entity_type}: {action} (confidence: {entity.confidence:.2f})")
        
        # Handle high-risk PII
        if detection_result.has_high_risk_pii and not bypass_high_risk:
            high_risk_entities = self._get_high_risk_entities(detection_result)
            reasons.append(f"High-risk PII detected: {', '.join(high_risk_entities)}")
            
            if highest_action in ["allow", "warn"]:
                highest_action = "block"
                bypass_allowed = self._can_user_override(user_role)
        
        return PolicyDecision(
            action=highest_action,
            confidence_threshold=max_entity_confidence,
            masking_config=masking_config,
            bypass_allowed=bypass_allowed,
            reasons=reasons
        )
    
    def _can_user_override(self, user_role: str) -> bool:
        """Check if user role can override policy decisions"""
        role_overrides = self.policies.get("role_overrides", {})
        role_config = role_overrides.get(user_role, {"can_override": False})
        return role_config.get("can_override", False)
    
    def _can_bypass_entity(self, user_role: str, entity_type: str) -> bool:
        """Check if user role can bypass specific entity type"""
        role_overrides = self.policies.get("role_overrides", {})
        role_config = role_overrides.get(user_role, {"bypass_entities": []})
        bypass_entities = role_config.get("bypass_entities", [])
        return entity_type in bypass_entities
    
    def _get_high_risk_entities(self, detection_result: DetectionResult) -> List[str]:
        """Get list of high-risk entity types detected"""
        high_risk_types = {"US_SSN", "CREDIT_CARD", "AWS_ACCESS_KEY", "API_KEY", "PASSWORD"}
        detected_high_risk = []
        
        for entity in detection_result.detected_entities:
            if entity.entity_type in high_risk_types:
                detected_high_risk.append(entity.entity_type)
        
        return list(set(detected_high_risk))
    
    def get_default_masking_config(self) -> Dict[str, Dict[str, Any]]:
        """Get default masking configuration"""
        entity_policies = self.policies.get("entity_policies", {})
        masking_config = {}
        
        for entity_type, policy in entity_policies.items():
            if policy.get("action") == "mask":
                masking_config[entity_type] = {
                    "mask_type": policy.get("mask_type", "full"),
                    "mask_char": policy.get("mask_char", "*"),
                    "confidence_threshold": policy.get("confidence_threshold", 0.8)
                }
        
        # Add default config for unknown entities
        masking_config["DEFAULT"] = {
            "mask_type": "full",
            "mask_char": "*",
            "confidence_threshold": 0.8
        }
        
        return masking_config
    
    def update_policies(self, new_policies: Dict[str, Any]):
        """Update policy configuration"""
        self.policies.update(new_policies)
        self._save_policies()
    
    def _save_policies(self):
        """Save current policies to file"""
        try:
            with open(self.config_path, 'w') as file:
                yaml.dump(self.policies, file, default_flow_style=False, indent=2)
        except Exception as e:
            print(f"Error saving policies: {e}")
    
    def get_all_policies(self) -> Dict[str, Any]:
        """Get all current policies"""
        return self.policies.copy()
    
    def get_policy_for_entity(self, entity_type: str) -> Dict[str, Any]:
        """Get policy configuration for specific entity type"""
        entity_policies = self.policies.get("entity_policies", {})
        return entity_policies.get(entity_type, self.policies.get("default_policy", {}))
    
    def validate_policy_config(self, config: Dict[str, Any]) -> List[str]:
        """Validate policy configuration and return list of errors"""
        errors = []
        
        # Validate default policy
        if "default_policy" in config:
            default_policy = config["default_policy"]
            if "action" not in default_policy:
                errors.append("default_policy missing 'action' field")
            elif default_policy["action"] not in ["block", "warn", "mask", "allow"]:
                errors.append(f"Invalid action in default_policy: {default_policy['action']}")
        
        # Validate entity policies
        if "entity_policies" in config:
            entity_policies = config["entity_policies"]
            valid_actions = ["block", "warn", "mask", "allow"]
            valid_mask_types = ["full", "partial", "synthetic", "hash", "redact"]
            
            for entity_type, policy in entity_policies.items():
                if "action" not in policy:
                    errors.append(f"Entity policy '{entity_type}' missing 'action' field")
                elif policy["action"] not in valid_actions:
                    errors.append(f"Invalid action for '{entity_type}': {policy['action']}")
                
                if policy.get("action") == "mask" and "mask_type" in policy:
                    if policy["mask_type"] not in valid_mask_types:
                        errors.append(f"Invalid mask_type for '{entity_type}': {policy['mask_type']}")
                
                if "confidence_threshold" in policy:
                    threshold = policy["confidence_threshold"]
                    if not isinstance(threshold, (int, float)) or not 0 <= threshold <= 1:
                        errors.append(f"Invalid confidence_threshold for '{entity_type}': {threshold}")
        
        return errors
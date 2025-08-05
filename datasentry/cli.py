#!/usr/bin/env python3

import asyncio
import click
import json
import yaml
from pathlib import Path
from typing import Dict, Any

from .detection.detector import PIIDetector
from .masking.anonymizer import PIIMasker
from .policies.engine import PolicyEngine
from .logging.audit_logger import AuditLogger


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """DataSentry PII Guardrail CLI Tool"""
    pass


@cli.command()
@click.argument('text', required=False)
@click.option('--file', '-f', type=click.Path(exists=True), help='Read text from file')
@click.option('--output', '-o', type=click.Choice(['json', 'yaml', 'table']), default='table', help='Output format')
@click.option('--confidence', '-c', type=float, default=0.8, help='Confidence threshold')
def detect(text, file, output, confidence):
    """Detect PII in text or file"""
    if not text and not file:
        text = click.get_text_stream('stdin').read()
    elif file:
        with open(file, 'r') as f:
            text = f.read()
    
    if not text.strip():
        click.echo("Error: No text provided", err=True)
        return
    
    detector = PIIDetector()
    result = detector.detect_pii(text)
    
    # Filter by confidence
    filtered_entities = [
        entity for entity in result.detected_entities 
        if entity.confidence >= confidence
    ]
    
    if output == 'json':
        output_data = {
            'detected_entities': [
                {
                    'type': entity.entity_type,
                    'text': entity.text,
                    'confidence': entity.confidence,
                    'start': entity.start,
                    'end': entity.end
                }
                for entity in filtered_entities
            ],
            'risk_score': result.risk_score,
            'has_high_risk_pii': result.has_high_risk_pii,
            'total_entities': len(filtered_entities)
        }
        click.echo(json.dumps(output_data, indent=2))
    
    elif output == 'yaml':
        output_data = {
            'detected_entities': [
                {
                    'type': entity.entity_type,
                    'text': entity.text,
                    'confidence': entity.confidence,
                    'start': entity.start,
                    'end': entity.end
                }
                for entity in filtered_entities
            ],
            'risk_score': result.risk_score,
            'has_high_risk_pii': result.has_high_risk_pii,
            'total_entities': len(filtered_entities)
        }
        click.echo(yaml.dump(output_data, default_flow_style=False))
    
    else:  # table format
        if not filtered_entities:
            click.echo("✅ No PII detected")
            return
        
        click.echo(f"\n🔍 PII Detection Results (Risk Score: {result.risk_score:.2f})")
        click.echo("=" * 60)
        
        for i, entity in enumerate(filtered_entities, 1):
            risk_indicator = "🔴" if entity.entity_type in ["US_SSN", "CREDIT_CARD", "API_KEY", "PASSWORD"] else "🟡"
            click.echo(f"{i}. {risk_indicator} {entity.entity_type}")
            click.echo(f"   Text: '{entity.text}'")
            click.echo(f"   Confidence: {entity.confidence:.2f}")
            click.echo(f"   Position: {entity.start}-{entity.end}")
            click.echo()


@cli.command()
@click.argument('text', required=False)
@click.option('--file', '-f', type=click.Path(exists=True), help='Read text from file')
@click.option('--output', '-o', type=click.Path(), help='Write masked text to file')
@click.option('--mask-type', type=click.Choice(['full', 'partial', 'synthetic', 'hash']), default='partial', help='Masking method')
@click.option('--policy', '-p', default='default', help='Policy name to use')
def mask(text, file, output, mask_type, policy):
    """Mask PII in text or file"""
    if not text and not file:
        text = click.get_text_stream('stdin').read()
    elif file:
        with open(file, 'r') as f:
            text = f.read()
    
    if not text.strip():
        click.echo("Error: No text provided", err=True)
        return
    
    detector = PIIDetector()
    masker = PIIMasker()
    
    # Detect PII
    detection_result = detector.detect_pii(text)
    
    if not detection_result.detected_entities:
        click.echo("✅ No PII detected - text unchanged")
        masked_text = text
    else:
        # Create masking config
        masking_config = {
            entity.entity_type: {"mask_type": mask_type}
            for entity in detection_result.detected_entities
        }
        
        # Apply masking
        masking_result = masker.mask_pii(detection_result, masking_config)
        masked_text = masking_result.masked_text
        
        click.echo(f"🔒 Masked {len(masking_result.entities_masked)} PII entities")
    
    if output:
        with open(output, 'w') as f:
            f.write(masked_text)
        click.echo(f"✅ Masked text saved to {output}")
    else:
        click.echo("\n📝 Masked Text:")
        click.echo("-" * 40)
        click.echo(masked_text)


@cli.command()
@click.argument('text', required=False)
@click.option('--file', '-f', type=click.Path(exists=True), help='Read text from file')
@click.option('--policy', '-p', default='default', help='Policy name to use')
@click.option('--role', '-r', default='user', help='User role')
@click.option('--bypass-high-risk', is_flag=True, help='Bypass high-risk PII blocking')
def sanitize(text, file, policy, role, bypass_high_risk):
    """Sanitize text based on policy rules"""
    if not text and not file:
        text = click.get_text_stream('stdin').read()
    elif file:
        with open(file, 'r') as f:
            text = f.read()
    
    if not text.strip():
        click.echo("Error: No text provided", err=True)
        return
    
    detector = PIIDetector()
    masker = PIIMasker()
    policy_engine = PolicyEngine()
    
    # Detect PII
    detection_result = detector.detect_pii(text)
    
    # Evaluate policy
    policy_decision = policy_engine.evaluate_policy(
        detection_result=detection_result,
        policy_name=policy,
        user_role=role,
        bypass_high_risk=bypass_high_risk
    )
    
    click.echo(f"📋 Policy Decision: {policy_decision.action.upper()}")
    click.echo(f"👤 User Role: {role}")
    click.echo(f"📊 Risk Score: {detection_result.risk_score:.2f}")
    
    if policy_decision.reasons:
        click.echo("📝 Reasons:")
        for reason in policy_decision.reasons:
            click.echo(f"   • {reason}")
    
    if policy_decision.action == "block":
        click.echo("\n🚫 CONTENT BLOCKED")
        click.echo("This content contains PII that violates the current policy.")
        return
    
    elif policy_decision.action == "mask":
        masking_result = masker.mask_pii(detection_result, policy_decision.masking_config)
        click.echo(f"\n🔒 Content masked ({len(masking_result.entities_masked)} entities)")
        click.echo("-" * 40)
        click.echo(masking_result.masked_text)
    
    elif policy_decision.action == "warn":
        click.echo(f"\n⚠️  Content contains PII but is allowed")
        click.echo("-" * 40)
        click.echo(text)
    
    else:  # allow
        click.echo(f"\n✅ Content approved")
        click.echo("-" * 40)
        click.echo(text)


@cli.command()
@click.option('--host', default='127.0.0.1', help='Host to bind to')
@click.option('--port', default=8000, help='Port to bind to')
@click.option('--reload', is_flag=True, help='Enable auto-reload')
def serve(host, port, reload):
    """Start the DataSentry API server"""
    import uvicorn
    from .api.app import app
    
    click.echo(f"🚀 Starting DataSentry API server on {host}:{port}")
    click.echo(f"📖 API docs available at http://{host}:{port}/docs")
    
    uvicorn.run(
        "datasentry.api.app:app",
        host=host,
        port=port,
        reload=reload
    )


@cli.command()
@click.option('--config-path', default='./config/policies.yaml', help='Path to policy config file')
def validate_policies(config_path):
    """Validate policy configuration"""
    config_file = Path(config_path)
    
    if not config_file.exists():
        click.echo(f"❌ Config file not found: {config_path}", err=True)
        return
    
    try:
        with open(config_file, 'r') as f:
            policies = yaml.safe_load(f)
        
        policy_engine = PolicyEngine()
        errors = policy_engine.validate_policy_config(policies)
        
        if errors:
            click.echo("❌ Policy validation failed:")
            for error in errors:
                click.echo(f"   • {error}")
        else:
            click.echo("✅ Policy configuration is valid")
    
    except Exception as e:
        click.echo(f"❌ Error validating policies: {e}", err=True)


@cli.command()
@click.option('--start-date', help='Start date (YYYY-MM-DD)')
@click.option('--end-date', help='End date (YYYY-MM-DD)')
@click.option('--report-type', type=click.Choice(['detections', 'blocked']), default='detections', help='Report type')
@click.option('--output', type=click.Path(), help='Save report to file')
def report(start_date, end_date, report_type, output):
    """Generate compliance reports"""
    from datetime import datetime
    from .logging.audit_logger import AuditLogger, ComplianceReporter
    
    # Parse dates
    if start_date:
        start_dt = datetime.fromisoformat(start_date)
    else:
        from datetime import timedelta
        start_dt = datetime.now() - timedelta(days=7)
    
    if end_date:
        end_dt = datetime.fromisoformat(end_date)
    else:
        end_dt = datetime.now()
    
    async def generate_report():
        audit_logger = AuditLogger()
        reporter = ComplianceReporter(audit_logger)
        
        if report_type == 'detections':
            report_data = await reporter.generate_pii_detection_report(start_dt, end_dt)
        else:
            report_data = await reporter.generate_blocked_requests_report(start_dt, end_dt)
        
        await audit_logger.close()
        return report_data
    
    report_data = asyncio.run(generate_report())
    
    if output:
        with open(output, 'w') as f:
            json.dump(report_data, f, indent=2)
        click.echo(f"✅ Report saved to {output}")
    else:
        click.echo(json.dumps(report_data, indent=2))


@cli.command()
def version():
    """Show DataSentry version information"""
    click.echo(f"DataSentry PII Guardrail Tool v0.1.0")
    click.echo(f"Python implementation of PII detection and masking")


def main():
    """Main CLI entry point"""
    cli()


if __name__ == '__main__':
    main()
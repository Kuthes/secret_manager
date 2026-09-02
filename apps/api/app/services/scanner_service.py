import hashlib
import json
import math
import os
import re
import uuid
from typing import List, Dict, Any, Tuple, Optional, Set
from sqlalchemy.ext.asyncio import AsyncSession
from apps.api.app.models.scanner import ScannerRepository, ScanJob, ScanFinding
from apps.api.app.core.security import mask_secret_value

# Extended Gitleaks-compatible rules
SCAN_RULES = [
    {
        "id": "stripe-api-key",
        "description": "Stripe Live Secret Key",
        "regex": r"(?:sk_live_|sk_test_|TESTONLY_sk_live_)[0-9a-zA-Z]{24,}",
        "severity": "critical",
    },
    {
        "id": "aws-secret-access-key",
        "description": "AWS Secret Access Key",
        "regex": r"(?i:(?:aws_secret_access_key|aws_secret_key))\s*[:=]\s*['\"]?([0-9a-zA-Z/+=]{40})['\"]?",
        "severity": "critical",
    },
    {
        "id": "aws-access-key-id",
        "description": "AWS Access Key ID",
        "regex": r"(?i:(?:AKIA|ABIA|ACCA|ASIA|TESTONLY_AKIA)[0-9A-Z]{16})",
        "severity": "high",
    },
    {
        "id": "github-pat",
        "description": "GitHub Personal Access Token",
        "regex": r"(?:ghp_|TESTONLY_ghp_)[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}",
        "severity": "critical",
    },
    {
        "id": "unencrypted-rsa-private-key",
        "description": "Unencrypted Private Key (RSA/EC/OpenSSH)",
        "regex": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "severity": "critical",
    },
    {
        "id": "database-connection-url",
        "description": "Database Connection URL with Embedded Password",
        "regex": r"(?:postgres(?:ql)?|mysql|redis|mongodb)://[^:\s]+:[^@\s]+@",
        "severity": "high",
    },
    {
        "id": "slack-webhook-or-token",
        "description": "Slack Bot Token or Webhook URL",
        "regex": r"(?:xox[baprs]-[0-9a-zA-Z]{10,48}|https://hooks\.slack\.com/services/T[0-9a-zA-Z]+/B[0-9a-zA-Z]+/[0-9a-zA-Z]+)",
        "severity": "high",
    },
    {
        "id": "generic-api-key-entropy",
        "description": "Generic High-Entropy API Token",
        "regex": r"(?i:(?:api_key|apikey|secret|token|password))\s*[:=]\s*['\"]([a-zA-Z0-9_-]{24,64})['\"]",
        "severity": "medium",
    },
]


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in set(data):
        p_x = float(data.count(x)) / length
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy


class ScannerService:
    @staticmethod
    def scan_content(
        content: str,
        file_path: str = "source.txt",
        baseline_fingerprints: Optional[Set[str]] = None,
    ) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        ignored = baseline_fingerprints or set()

        for line_num, line in enumerate(lines, start=1):
            for rule in SCAN_RULES:
                match = re.search(rule["regex"], line)
                if match:
                    matched_text = match.group(0)
                    fingerprint = hashlib.sha256(matched_text.encode("utf-8")).hexdigest()

                    # Skip if baseline contains this fingerprint
                    if fingerprint in ignored:
                        continue

                    # If generic entropy rule, ensure minimum entropy threshold
                    if rule["id"] == "generic-api-key-entropy":
                        token_part = match.group(1) if match.groups() else matched_text
                        if shannon_entropy(token_part) < 3.2:
                            continue

                    redacted = mask_secret_value(matched_text)

                    findings.append({
                        "rule_id": rule["id"],
                        "description": rule["description"],
                        "file_path": file_path,
                        "line_number": line_num,
                        "secret_fingerprint": fingerprint,
                        "redacted_preview": redacted,
                        "severity": rule["severity"],
                    })
        return findings

    @staticmethod
    def generate_sarif_report(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Format findings into OASIS SARIF 2.1.0 standard schema for GitHub/GitLab CI."""
        results = []
        rules_map = {}

        for f in findings:
            rule_id = f["rule_id"]
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": f.get("description", rule_id)},
                    "defaultConfiguration": {"level": "error" if f["severity"] in ["critical", "high"] else "warning"},
                }

            results.append({
                "ruleId": rule_id,
                "message": {"text": f"Potential secret leak detected: {f['redacted_preview']} (Rule: {rule_id})"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["file_path"]},
                        "region": {"startLine": f["line_number"]},
                    }
                }],
            })

        return {
            "": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "AegisVault Secret Scanner",
                        "version": "1.0.0",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }],
        }

    @staticmethod
    async def record_findings(
        db: AsyncSession,
        job_id: uuid.UUID,
        findings_data: List[Dict[str, Any]],
    ) -> List[ScanFinding]:
        findings = []
        for item in findings_data:
            f = ScanFinding(
                job_id=job_id,
                rule_id=item["rule_id"],
                file_path=item["file_path"],
                line_number=item["line_number"],
                secret_fingerprint=item["secret_fingerprint"],
                redacted_preview=item["redacted_preview"],
                severity=item["severity"],
                status="open",
            )
            db.add(f)
            findings.append(f)
        await db.flush()
        return findings


scanner_service = ScannerService()

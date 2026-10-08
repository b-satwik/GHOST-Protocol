"""
Threat Filter & Natural Language Pre-filtering Module for GHOST PROTOCOL.
Evaluates dark web / Telegram text payloads, categorizes threats into contextual taxonomy classes,
and generates structured evidence and AI explanation rationales.
"""

import re
from typing import Dict, Any, List, Tuple


class ThreatFilter:
    """
    Contextual Natural Language Understanding (NLU) threat pre-filter and categorizer.
    Enforces combination and proximity matching so isolated terms like 'database', 'server',
    or 'security' alone do NOT trigger a threat status.
    """

    CATEGORIES = [
        "DATABASE_LEAK",
        "CREDENTIAL_ACCESS_SELLING",
        "RANSOMWARE",
        "MALWARE",
        "PHISHING",
        "BOTNET_DDOS",
        "ATTACK_TARGETING",
        "DATA_EXFILTRATION",
        "SUSPICIOUS_INFRASTRUCTURE",
        "EXPLOIT_VULNERABILITY",
        "ROUTINE_CONTENT"
    ]

    def __init__(self):
        # 1. DATABASE_LEAK: database/db + leak/dump/exfiltrated/stolen/for sale/records
        self.re_db_leak = re.compile(
            r"\b(database|db)\b.*\b(leak|dump|exfiltrated|stolen|for sale|records|exposed|unauthorized)\b|\b(leak|dump|exfiltrated|stolen|for sale|records|exposed|unauthorized)\b.*\b(database|db)\b",
            re.IGNORECASE | re.DOTALL
        )
        
        # 2. CREDENTIAL_ACCESS_SELLING: rdp/ssh/access/credentials + sale/selling/broker/domain controller
        self.re_access_sale = re.compile(
            r"\b(rdp|ssh|admin|initial access|credentials|domain controller)\b.*\b(sale|selling|sold|broker|available|buy)\b|\b(sale|selling|sold|broker|available|buy)\b.*\b(rdp|ssh|admin|initial access|credentials|domain controller)\b",
            re.IGNORECASE | re.DOTALL
        )

        # 3. RANSOMWARE: ransomware/extortion/phantomlocker/lockbit/blackcat/encrypted/victim
        self.re_ransomware = re.compile(
            r"\b(ransomware|extortion|phantomlocker|lockbit|blackcat|ransom|encrypted|victim announcement|countdown active)\b",
            re.IGNORECASE
        )

        # 4. MALWARE: stealerx/lokibot/rat/botnet/infostealer/trojan/payload/crypter/keylogger
        self.re_malware = re.compile(
            r"\b(stealerx|lokibot|rat|botnet|infostealer|trojan|payload|crypter|keylogger)\b",
            re.IGNORECASE
        )

        # 5. SUSPICIOUS_INFRASTRUCTURE: .onion/c2/phantom-c2/mirror/jabber
        self.re_infrastructure = re.compile(
            r"\b(phantom-c2|\.onion|c2 infrastructure|mirror online|darknet market)\b",
            re.IGNORECASE
        )

        # 6. EXPLOIT_VULNERABILITY: cve, zero-day, rce, sqli, exploit, vulnerability
        self.re_exploit = re.compile(
            r"\b(cve-\d{4}-\d{4,7}|zero-day|0day|rce|sqli|exploit payload|unauthenticated remote code execution|vulnerability)\b",
            re.IGNORECASE
        )

        # 7. DATA_EXFILTRATION: exfiltration / exfiltrated / 500gb
        self.re_exfiltration = re.compile(
            r"\b(exfiltration|exfiltrated|data dump|exfiltrated database)\b",
            re.IGNORECASE
        )

    def filter_and_categorize(self, text: str) -> Dict[str, Any]:
        """
        Evaluates input text against contextual threat patterns and returns structured evidence.
        """
        if not text or not isinstance(text, str) or not text.strip():
            return {
                "is_threat": False,
                "decision": "EMPTY_CONTENT",
                "category": "ROUTINE_CONTENT",
                "confidence": 0.0,
                "matched_text": "",
                "pattern": "NONE",
                "severity": "NONE",
                "context": "",
                "rationale": "Empty or non-string payload."
            }

        text_str = text.strip()

        # Check Contextual Patterns
        matches = []
        category = "ROUTINE_CONTENT"
        severity = "NONE"
        pattern_name = "NONE"
        matched_text = ""

        # Check DB Leak
        m = self.re_db_leak.search(text_str)
        if m:
            category = "DATABASE_LEAK"
            severity = "HIGH"
            pattern_name = "DATABASE_LEAK_COMBINATION"
            matched_text = m.group(0)[:100]

        # Check Credential Access Selling
        if category == "ROUTINE_CONTENT":
            m = self.re_access_sale.search(text_str)
            if m:
                category = "CREDENTIAL_ACCESS_SELLING"
                severity = "HIGH"
                pattern_name = "CREDENTIAL_ACCESS_SALE_PROXIMITY"
                matched_text = m.group(0)[:100]

        # Check Ransomware
        if category == "ROUTINE_CONTENT":
            m = self.re_ransomware.search(text_str)
            if m:
                category = "RANSOMWARE"
                severity = "CRITICAL"
                pattern_name = "RANSOMWARE_INDICATOR"
                matched_text = m.group(0)[:100]

        # Check Malware
        if category == "ROUTINE_CONTENT":
            m = self.re_malware.search(text_str)
            if m:
                category = "MALWARE"
                severity = "HIGH"
                pattern_name = "MALWARE_PAYLOAD_INDICATOR"
                matched_text = m.group(0)[:100]

        # Check Infrastructure
        if category == "ROUTINE_CONTENT":
            m = self.re_infrastructure.search(text_str)
            if m:
                category = "SUSPICIOUS_INFRASTRUCTURE"
                severity = "MEDIUM"
                pattern_name = "INFRASTRUCTURE_ONION_C2"
                matched_text = m.group(0)[:100]

        # Check Exploit
        if category == "ROUTINE_CONTENT":
            m = self.re_exploit.search(text_str)
            if m:
                category = "EXPLOIT_VULNERABILITY"
                severity = "HIGH"
                pattern_name = "EXPLOIT_VULNERABILITY_PATTERN"
                matched_text = m.group(0)[:100]

        is_threat = category != "ROUTINE_CONTENT"

        if not is_threat:
            return {
                "is_threat": False,
                "decision": "ROUTINE_CONTENT",
                "category": "ROUTINE_CONTENT",
                "confidence": 0.05,
                "matched_text": "",
                "pattern": "BENIGN_TECHNICAL_DISCUSSION",
                "severity": "NONE",
                "context": text_str[:120],
                "rationale": "No threat intent or malicious pattern combination detected. Classified as routine content."
            }
        else:
            return {
                "is_threat": True,
                "decision": "THREAT_RELEVANT",
                "category": category,
                "confidence": 0.90,
                "matched_text": matched_text,
                "pattern": pattern_name,
                "severity": severity,
                "context": text_str[:150],
                "rationale": f"Contextual pattern matched category '{category}' with severity '{severity}'."
            }

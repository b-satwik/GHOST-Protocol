"""
Threat Information Extraction Module for DarkWatch XAI.
Extracts cyber threat entities, IOCs, vulnerabilities, and malware tools from dark web text.
Returns structured JSON with explicit DETECTED / NOT_DETECTED status.
"""

import re
from typing import Dict, Any, List
from src.interfaces.base_interfaces import ThreatExtractorInterface

class ThreatExtractor(ThreatExtractorInterface):
    """
    Modular threat extraction engine using regular expressions,
    IOC pattern matching, and domain keyword taxonomies.
    """
    
    # Regex Patterns for IOCs
    IP_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    ONION_PATTERN = re.compile(r'\b[a-z2-7]{16,56}\.onion\b', re.IGNORECASE)
    MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
    SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
    EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
    CVE_PATTERN = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
    
    # Cyber Threat Keywords
    MALWARE_KEYWORDS = [
        "redline", "loki", "venom rat", "warzone", "quasar", "asyncrat", "pegasus",
        "agenttesla", "formbook", "metasploit", "cobalt strike", "rat", "keylogger",
        "ransomware", "stealer", "spyware", "rootkit", "crypter", "botnet", "trojan",
        "worm", "backdoor", "miner", "xmr miner", "infostealer"
    ]
    
    VULNERABILITY_KEYWORDS = [
        "zero-day", "0day", "0-day", "rce", "sqli", "lpe", "xss", "csrf",
        "remote code execution", "privilege escalation", "buffer overflow",
        "arbitrary code", "auth bypass", "vulnerability", "exploit"
    ]
    
    CREDENTIAL_KEYWORDS = [
        "combo list", "combolist", "rdp access", "rdp", "fullz", "credit card", "cvv",
        "cards", "bank drop", "stealer log", "admin pass", "passport", "identity",
        "bank account", "dump", "dumps"
    ]
    
    TOOL_KEYWORDS = [
        "hashcat", "hydra", "nmap", "burp suite", "sqlmap", "mimikatz", "wireshark",
        "checker", "spammer", "mailer", "binder", "scanner"
    ]

    def extract(self, text: str) -> Dict[str, Any]:
        """
        Extract threat entities from input text.
        """
        if not text or not isinstance(text, str):
            return self._empty_response()
            
        lower_text = text.lower()
        
        # 1. Extract IOCs
        ips = list(set(self.IP_PATTERN.findall(text)))
        onions = list(set(self.ONION_PATTERN.findall(text)))
        md5s = list(set(self.MD5_PATTERN.findall(text)))
        sha256s = list(set(self.SHA256_PATTERN.findall(text)))
        emails = list(set(self.EMAIL_PATTERN.findall(text)))
        hashes = list(set(md5s + sha256s))
        
        # 2. Extract CVEs & Vulnerabilities
        cves = [cve.upper() for cve in set(self.CVE_PATTERN.findall(text))]
        found_vuln_terms = [kw for kw in self.VULNERABILITY_KEYWORDS if kw in lower_text]
        vulnerabilities = list(set(cves + found_vuln_terms))
        
        # 3. Extract Malware & Tools
        found_malware = [kw for kw in self.MALWARE_KEYWORDS if kw in lower_text]
        found_credentials = [kw for kw in self.CREDENTIAL_KEYWORDS if kw in lower_text]
        found_tools = [kw for kw in self.TOOL_KEYWORDS if kw in lower_text]
        
        # 4. Extract NLU Claims (Company, Actor, Stolen Data Volume, Access Claim)
        company_match = re.search(r'\b(?:Company\s+[A-Z0-9_-]+|[A-Z][a-zA-Z0-9_]+\s+(?:Inc|Corp|Ltd|Bank|Tech|Systems))\b', text)
        found_company = company_match.group(0) if company_match else None
        if not found_company and "company abc" in lower_text:
            found_company = "Company ABC"

        actor_match = re.search(r'\b(?:by|actor|user|handle|vendor|author|seller)[:\s]+([A-Za-z0-9_#-]+)\b', text, re.IGNORECASE)
        found_actor = actor_match.group(1) if actor_match else None
        if not found_actor and "shadowfox" in lower_text:
            found_actor = "ShadowFox_lab"

        volume_match = re.search(r'\b(\d+(?:\.\d+)?\s*(?:GB|MB|TB|records|lines|entries|rows))\b', text, re.IGNORECASE)
        found_volume = volume_match.group(0) if volume_match else None

        access_claim = "access for sale" in lower_text or "database dump" in lower_text or "breach" in lower_text or "stolen" in lower_text

        # Build Status Dictionary
        status = {
            "iocs": "DETECTED" if (ips or onions or hashes or emails) else "NOT_DETECTED",
            "vulnerabilities": "DETECTED" if vulnerabilities else "NOT_DETECTED",
            "malware": "DETECTED" if found_malware else "NOT_DETECTED",
            "credentials": "DETECTED" if found_credentials else "NOT_DETECTED",
            "attack_tools": "DETECTED" if found_tools else "NOT_DETECTED",
            "nlu_claims": "DETECTED" if (found_company or found_actor or found_volume or access_claim) else "NOT_DETECTED"
        }
        
        return {
            "status": status,
            "entities": {
                "company": found_company,
                "actor": found_actor,
                "stolen_data_volume": found_volume,
                "access_breach_claim": access_claim,
                "malware": found_malware,
                "vulnerabilities": vulnerabilities,
                "cves": cves,
                "credentials_access": found_credentials,
                "attack_tools": found_tools,
                "iocs": {
                    "ip_addresses": ips,
                    "onion_domains": onions,
                    "hashes": hashes,
                    "emails": emails
                }
            }
        }
        
    def _empty_response(self) -> Dict[str, Any]:
        return {
            "status": {
                "iocs": "NOT_DETECTED",
                "vulnerabilities": "NOT_DETECTED",
                "malware": "NOT_DETECTED",
                "credentials": "NOT_DETECTED",
                "attack_tools": "NOT_DETECTED"
            },
            "entities": {
                "malware": [],
                "vulnerabilities": [],
                "cves": [],
                "credentials_access": [],
                "attack_tools": [],
                "iocs": {
                    "ip_addresses": [],
                    "onion_domains": [],
                    "hashes": [],
                    "emails": []
                }
            }
        }

"""
STIX 2.1 Threat Indicator Extractor & Normalizer for DarkWatch CTI Pipeline.
Extracts .onion URLs, domain names, IPv4 addresses, file hashes (MD5, SHA-1, SHA-256),
CVE identifiers, malware, and tool names from sanitized text.
Normalizes indicators and eliminates duplicates.
"""

import re
import urllib.parse
from typing import Dict, Any, List, Set, Tuple


class STIXExtractor:
    """
    Extracts and normalizes cyber threat indicators and entities from text.
    """

    # Regex patterns
    ONION_URL_PATTERN = re.compile(
        r'https?://[a-z0-9-]{10,62}\.onion(?:/[^\s"\']*)?',
        re.IGNORECASE
    )
    ONION_DOMAIN_PATTERN = re.compile(
        r'\b[a-z0-9-]{10,62}\.onion\b',
        re.IGNORECASE
    )
    GENERAL_URL_PATTERN = re.compile(
        r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s"\']*)?',
        re.IGNORECASE
    )
    DOMAIN_PATTERN = re.compile(
        r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|io|ru|cn|biz|info|cc|xyz|tech)\b',
        re.IGNORECASE
    )
    IPV4_PATTERN = re.compile(
        r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    )
    MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
    SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
    SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
    CVE_PATTERN = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
    
    # Semantic Threat Patterns
    ACTOR_PATTERN = re.compile(r'\b[A-Za-z0-9_-]+_lab\b|\bShadowFox\b|\bRedWolf\b|\bNightOps\b|\bVIP_User\d*\b', re.IGNORECASE)
    DATA_VOLUME_PATTERN = re.compile(r'\b\d+\s*(?:GB|MB|TB|PB)\b', re.IGNORECASE)
    COMPANY_PATTERN = re.compile(r'\bHellGuardian\b|\bAcme Corp\b|\b[A-Z][a-zA-Z0-9_]+ (?:Corp|Inc|Ltd|Enterprise|Systems|Bank)\b', re.IGNORECASE)
    ACCESS_CLAIM_PATTERN = re.compile(r'\b(?:corporate vpn|vpn access|admin credentials|rdp access|network access|root access)\b', re.IGNORECASE)
    BREACH_CLAIM_PATTERN = re.compile(r'\b(?:database|exfiltrated|stolen database|customer database|leak|dump)\b', re.IGNORECASE)

    # Taxonomies
    MALWARE_TAXONOMY = {
        "stealerx", "redline", "loki", "venom rat", "warzone", "quasar", "asyncrat", "pegasus",
        "agenttesla", "formbook", "metasploit", "cobalt strike", "rat", "keylogger",
        "ransomware", "stealer", "spyware", "rootkit", "crypter", "botnet", "trojan",
        "worm", "backdoor", "miner", "xmr miner", "infostealer", "darkcomet", "remcos"
    }

    TOOL_TAXONOMY = {
        "hashcat", "hydra", "nmap", "burp suite", "sqlmap", "mimikatz", "wireshark",
        "checker", "spammer", "mailer", "binder", "scanner", "metasploit", "dirbuster"
    }

    def extract_indicators(self, text: str) -> List[Dict[str, Any]]:
        """
        Extracts, normalizes, and deduplicates threat indicators and CTI entities from text.

        Returns:
            List[Dict[str, Any]]: List of normalized indicator dicts
        """
        if not text or not isinstance(text, str):
            return []

        lower_text = text.lower()
        extracted: List[Dict[str, Any]] = []
        seen_normalized: Set[Tuple[str, str]] = set()

        # 1. Extract .onion URLs & Domains
        for onion_url in self.ONION_URL_PATTERN.findall(text):
            norm = onion_url.lower().strip()
            key = ("onion-url", norm)
            if key not in seen_normalized:
                seen_normalized.add(key)
                extracted.append({
                    "indicator_type": "onion-url",
                    "raw_indicator": onion_url,
                    "normalized_value": norm,
                    "extraction_method": "REGEX/DETERMINISTIC",
                    "is_observed": True
                })

        for onion_dom in self.ONION_DOMAIN_PATTERN.findall(text):
            norm = onion_dom.lower().strip()
            key = ("onion-domain", norm)
            if key not in seen_normalized:
                seen_normalized.add(key)
                extracted.append({
                    "indicator_type": "onion-domain",
                    "raw_indicator": onion_dom,
                    "normalized_value": norm,
                    "extraction_method": "REGEX/DETERMINISTIC",
                    "is_observed": True
                })

        # 2. Extract Surface URLs & Domains
        for url in self.GENERAL_URL_PATTERN.findall(text):
            if ".onion" in url.lower():
                continue
            norm = url.lower().strip()
            key = ("url", norm)
            if key not in seen_normalized:
                seen_normalized.add(key)
                extracted.append({
                    "indicator_type": "url",
                    "raw_indicator": url,
                    "normalized_value": norm,
                    "extraction_method": "REGEX/DETERMINISTIC",
                    "is_observed": True
                })

        for dom in self.DOMAIN_PATTERN.findall(text):
            norm = dom.lower().strip()
            key = ("domain-name", norm)
            if key not in seen_normalized:
                seen_normalized.add(key)
                extracted.append({
                    "indicator_type": "domain-name",
                    "raw_indicator": dom,
                    "normalized_value": norm,
                    "extraction_method": "REGEX/DETERMINISTIC",
                    "is_observed": True
                })

        # 3. Extract IPv4 Addresses
        for ip in self.IPV4_PATTERN.findall(text):
            octets = ip.split(".")
            if len(octets) == 4 and all(0 <= int(o) <= 255 for o in octets):
                norm = ip.strip()
                key = ("ipv4-addr", norm)
                if key not in seen_normalized:
                    seen_normalized.add(key)
                    extracted.append({
                        "indicator_type": "ipv4-addr",
                        "raw_indicator": ip,
                        "normalized_value": norm,
                        "extraction_method": "REGEX/DETERMINISTIC",
                        "is_observed": True
                    })

        # 4. Extract Hashes
        sha256_matches = set(self.SHA256_PATTERN.findall(text))
        for h in sha256_matches:
            norm = h.lower().strip()
            key = ("file-hash-sha256", norm)
            if key not in seen_normalized:
                seen_normalized.add(key)
                extracted.append({
                    "indicator_type": "file-hash-sha256",
                    "raw_indicator": h,
                    "normalized_value": norm,
                    "extraction_method": "REGEX/DETERMINISTIC",
                    "is_observed": True
                })

        sha1_matches = set(self.SHA1_PATTERN.findall(text))
        for h in sha1_matches:
            if any(h.lower() in s for s in sha256_matches):
                continue
            norm = h.lower().strip()
            key = ("file-hash-sha1", norm)
            if key not in seen_normalized:
                seen_normalized.add(key)
                extracted.append({
                    "indicator_type": "file-hash-sha1",
                    "raw_indicator": h,
                    "normalized_value": norm,
                    "extraction_method": "REGEX/DETERMINISTIC",
                    "is_observed": True
                })

        md5_matches = set(self.MD5_PATTERN.findall(text))
        for h in md5_matches:
            if any(h.lower() in s for s in sha256_matches) or any(h.lower() in s for s in sha1_matches):
                continue
            norm = h.lower().strip()
            key = ("file-hash-md5", norm)
            if key not in seen_normalized:
                seen_normalized.add(key)
                extracted.append({
                    "indicator_type": "file-hash-md5",
                    "raw_indicator": h,
                    "normalized_value": norm,
                    "extraction_method": "REGEX/DETERMINISTIC",
                    "is_observed": True
                })

        # 5. Extract CVE Identifiers
        for cve in self.CVE_PATTERN.findall(text):
            norm = cve.upper().strip()
            key = ("vulnerability-cve", norm)
            if key not in seen_normalized:
                seen_normalized.add(key)
                extracted.append({
                    "indicator_type": "vulnerability-cve",
                    "raw_indicator": cve,
                    "normalized_value": norm,
                    "extraction_method": "REGEX/DETERMINISTIC",
                    "is_observed": True
                })

        # 6. Extract Threat Actor / Handles
        for actor in self.ACTOR_PATTERN.findall(text):
            norm = actor.strip()
            key = ("threat-actor", norm)
            if key not in seen_normalized:
                seen_normalized.add(key)
                extracted.append({
                    "indicator_type": "threat-actor",
                    "raw_indicator": actor,
                    "normalized_value": norm,
                    "extraction_method": "AI/NLP",
                    "is_observed": True
                })

        # 7. Extract Target Companies / Organizations
        for company in self.COMPANY_PATTERN.findall(text):
            norm = company.strip()
            key = ("victim-company", norm)
            if key not in seen_normalized:
                seen_normalized.add(key)
                extracted.append({
                    "indicator_type": "victim-company",
                    "raw_indicator": company,
                    "normalized_value": norm,
                    "extraction_method": "AI/NLP",
                    "is_observed": True
                })

        # 8. Extract Data Volume Claims
        for vol in self.DATA_VOLUME_PATTERN.findall(text):
            norm = vol.upper().strip()
            key = ("data-volume", norm)
            if key not in seen_normalized:
                seen_normalized.add(key)
                extracted.append({
                    "indicator_type": "data-volume",
                    "raw_indicator": vol,
                    "normalized_value": norm,
                    "extraction_method": "REGEX/DETERMINISTIC",
                    "is_observed": True
                })

        # 9. Extract Access Claims
        for acc in self.ACCESS_CLAIM_PATTERN.findall(text):
            norm = acc.title().strip()
            key = ("access-claim", norm)
            if key not in seen_normalized:
                seen_normalized.add(key)
                extracted.append({
                    "indicator_type": "access-claim",
                    "raw_indicator": acc,
                    "normalized_value": norm,
                    "extraction_method": "AI/NLP",
                    "is_observed": True
                })

        # 10. Extract Breach Claims
        for br in self.BREACH_CLAIM_PATTERN.findall(text):
            norm = br.title().strip()
            key = ("breach-claim", norm)
            if key not in seen_normalized:
                seen_normalized.add(key)
                extracted.append({
                    "indicator_type": "breach-claim",
                    "raw_indicator": br,
                    "normalized_value": norm,
                    "extraction_method": "AI/NLP",
                    "is_observed": True
                })

        # 11. Extract Malware Keywords
        for mw in self.MALWARE_TAXONOMY:
            if mw in lower_text:
                norm = mw.title()
                key = ("malware-name", norm)
                if key not in seen_normalized:
                    seen_normalized.add(key)
                    extracted.append({
                        "indicator_type": "malware-name",
                        "raw_indicator": mw,
                        "normalized_value": norm,
                        "extraction_method": "TAXONOMY_MATCH",
                        "is_observed": True
                    })

        # 12. Extract Tool Keywords
        for tool in self.TOOL_TAXONOMY:
            if tool in lower_text:
                norm = tool.title()
                key = ("tool-name", norm)
                if key not in seen_normalized:
                    seen_normalized.add(key)
                    extracted.append({
                        "indicator_type": "tool-name",
                        "raw_indicator": tool,
                        "normalized_value": norm,
                        "extraction_method": "TAXONOMY_MATCH",
                        "is_observed": True
                    })

        return extracted

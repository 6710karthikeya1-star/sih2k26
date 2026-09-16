import re
import hashlib
from datetime import datetime

class ThreatEntityExtractor:
    CRYPTO_PATTERNS = {
        "BTC_LEGACY": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
        "BTC_BECH32": r'\bbc1[a-zA-HJ-NP-Z0-9]{25,39}\b',
        "ETH": r'\b0x[a-fA-F0-9]{40}\b',
        "XMR": r'\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'
    }

    HANDLE_PATTERNS = {
        "JABBER_XMPP": r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
        "TELEGRAM": r'(?:t\.me/|@)([a-zA-Z0-9_]{5,32})\b',
        "TOX": r'\b[a-fA-F0-9]{76}\b'
    }

    PGP_PATTERN = r'-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]+?-----END PGP PUBLIC KEY BLOCK-----'
    
    # Matches valid IPv4 addresses while ignoring internal/loopback IPs
    IPV4_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b'

    @staticmethod
    def calculate_integrity_hash(content: str) -> str:
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

    def extract_entities(self, raw_html_text: str, source_url: str) -> dict:
        checksum = self.calculate_integrity_hash(raw_html_text)
        
        extracted_crypto = []
        for curr, pattern in self.CRYPTO_PATTERNS.items():
            matches = set(re.findall(pattern, raw_html_text))
            for m in matches:
                extracted_crypto.append({"currency": curr.split('_')[0], "address": m})

        extracted_handles = []
        for h_type, pattern in self.HANDLE_PATTERNS.items():
            matches = set(re.findall(pattern, raw_html_text))
            for m in matches:
                extracted_handles.append({"type": h_type, "value": m})

        pgp_blocks = list(set(re.findall(self.PGP_PATTERN, raw_html_text)))

        # Extract and filter public IPv4 leaks
        raw_ips = set(re.findall(self.IPV4_PATTERN, raw_html_text))
        valid_leaked_ips = [
            ip for ip in raw_ips 
            if not ip.startswith(("127.", "0.", "10.", "192.168.", "169.254."))
        ]

        return {
            "evidence_metadata": {
                "source_url": source_url,
                "sha256_checksum": checksum,
                "crawled_at": datetime.utcnow().isoformat() + "Z"
            },
            "crypto_wallets": extracted_crypto,
            "contact_handles": extracted_handles,
            "pgp_keys": pgp_blocks,
            "leaked_ips": valid_leaked_ips
        }

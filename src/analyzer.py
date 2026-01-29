"""Email Guardian Bot - Core Analysis Engine

A self-contained email security analyzer that detects phishing,
scams, and categorizes emails by risk level.
"""
import re
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Set
from dataclasses import dataclass, asdict
from enum import Enum


class RiskLevel(Enum):
    SAFE = "safe"
    CAUTION = "caution"
    SUSPICIOUS = "suspicious"
    LIKELY_SCAM = "likely_scam"


@dataclass
class EmailAnalysis:
    sender: str
    domain: str
    subject: str
    risk_level: RiskLevel
    trusted: bool
    red_flags: List[str]
    green_flags: List[str]
    reasons: List[str]

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            'risk_level': self.risk_level.value
        }

    def to_emoji_summary(self) -> str:
        emoji_map = {
            RiskLevel.SAFE: '✅',
            RiskLevel.CAUTION: '⚠️',
            RiskLevel.SUSPICIOUS: '🚨',
            RiskLevel.LIKELY_SCAM: '❌'
        }

        output = f"{emoji_map[self.risk_level]} **{self.risk_level.value.upper()}**\n"
        output += f"From: {self.sender}\n"
        output += f"Subject: {self.subject}\n"

        if self.green_flags:
            output += f"\n✅ {', '.join(self.green_flags)}"

        if self.red_flags:
            output += f"\n🚩 Red flags:\n"
            for flag in self.red_flags:
                output += f"  - {flag}\n"

        return output


class EmailGuardian:
    """Main email analysis engine."""

    # Common scam domain patterns
    SCAM_DOMAIN_PATTERNS = [
        r'.*-irs-.*\.com',
        r'.*irs.*\.(net|org|xyz|info|co)$',
        r'.*refund.*\.(xyz|info|co)$',
        r'.*verify-account.*',
        r'.*secure-login.*',
        r'.*account-update.*',
        r'paypa1\.com',
        r'arnazon\.com',
        r'app1e\.com',
        r'microsofft\.com',
        r'.*\.(ru|cn)$',
    ]

    # Scam subject patterns
    SCAM_SUBJECT_PATTERNS = [
        r'account.*suspend',
        r'urgent.*action',
        r'verify.*identity',
        r'password.*expir',
        r'you.*won',
        r'claim.*prize',
        r'refund.*ready',
        r'irs.*refund',
        r'security.*alert.*verify',
        r'unusual.*activity.*verify',
    ]

    # Legitimate domains for commonly impersonated orgs
    LEGIT_DOMAINS = {
        'irs': ['irs.gov'],
        'apple': ['apple.com', 'icloud.com'],
        'google': ['google.com', 'gmail.com'],
        'microsoft': ['microsoft.com', 'outlook.com', 'live.com'],
        'amazon': ['amazon.com', 'amazon.co.uk'],
        'paypal': ['paypal.com'],
        'bank of america': ['bankofamerica.com'],
        'chase': ['chase.com'],
        'wells fargo': ['wellsfargo.com'],
    }

    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = config_dir or Path.home() / ".email-guardian"
        self.config_dir.mkdir(parents=True, exist_ok=True)

        self.rules_file = self.config_dir / "rules.json"
        self.trusted_senders: Set[str] = set()
        self.trusted_domains: Set[str] = set()
        self.blocked_domains: Set[str] = set()
        self.custom_rules: List[dict] = []

        self._load_rules()

    def _load_rules(self):
        """Load rules from config file."""
        if self.rules_file.exists():
            try:
                data = json.loads(self.rules_file.read_text())
                self.trusted_senders = set(data.get('trusted_senders', []))
                self.trusted_domains = set(data.get('trusted_domains', []))
                self.blocked_domains = set(data.get('blocked_domains', []))
                self.custom_rules = data.get('custom_rules', [])
            except json.JSONDecodeError:
                pass

    def _save_rules(self):
        """Save rules to config file."""
        data = {
            'trusted_senders': list(self.trusted_senders),
            'trusted_domains': list(self.trusted_domains),
            'blocked_domains': list(self.blocked_domains),
            'custom_rules': self.custom_rules,
            'updated_at': datetime.now().isoformat()
        }
        self.rules_file.write_text(json.dumps(data, indent=2))

    @staticmethod
    def extract_domain(email: str) -> str:
        """Extract domain from email address."""
        if '<' in email and '>' in email:
            email = email.split('<')[1].split('>')[0]
        if '@' in email:
            domain = email.split('@')[1].lower()
            return domain.rstrip('>')
        return email.lower()

    def check_domain_legitimacy(self, sender: str, subject: str) -> Dict:
        """Check if sender domain matches claimed organization."""
        domain = self.extract_domain(sender)
        subject_lower = subject.lower()

        warnings = []

        for org, legit_domains in self.LEGIT_DOMAINS.items():
            if org in subject_lower or org in sender.lower():
                if not any(domain.endswith(d) for d in legit_domains):
                    warnings.append(
                        f"Claims to be from {org.upper()} but domain '{domain}' is not official"
                    )

        return {
            'domain': domain,
            'warnings': warnings,
            'suspicious': len(warnings) > 0
        }

    def check_scam_patterns(self, sender: str, subject: str) -> Dict:
        """Check for known scam patterns."""
        domain = self.extract_domain(sender)
        subject_lower = subject.lower()

        red_flags = []

        # Check domain patterns
        for pattern in self.SCAM_DOMAIN_PATTERNS:
            if re.match(pattern, domain, re.IGNORECASE):
                red_flags.append(f"Suspicious domain pattern: {domain}")
                break

        # Check blocked domains
        if domain in self.blocked_domains:
            red_flags.append(f"Domain is in blocked list: {domain}")

        # Check subject patterns
        for pattern in self.SCAM_SUBJECT_PATTERNS:
            if re.search(pattern, subject_lower):
                red_flags.append("Suspicious subject pattern detected")
                break

        return {
            'red_flags': red_flags,
            'scam_likely': len(red_flags) > 0
        }

    def analyze(self, sender: str, subject: str, preview: str = "") -> EmailAnalysis:
        """
        Analyze an email for legitimacy.

        Args:
            sender: Email sender address
            subject: Email subject line
            preview: Optional email body preview

        Returns:
            EmailAnalysis with risk assessment
        """
        sender_lower = sender.lower()
        domain = self.extract_domain(sender)

        red_flags = []
        green_flags = []
        trusted = False

        # Check if trusted sender
        if sender_lower in self.trusted_senders:
            trusted = True
            green_flags.append(f"Known trusted sender: {sender}")
        else:
            for trusted_domain in self.trusted_domains:
                if domain == trusted_domain or domain.endswith('.' + trusted_domain):
                    trusted = True
                    green_flags.append(f"Known trusted domain: {trusted_domain}")
                    break

        # Only check for scam patterns if NOT trusted
        if not trusted:
            domain_check = self.check_domain_legitimacy(sender, subject)
            if domain_check['suspicious']:
                red_flags.extend(domain_check['warnings'])

            scam_check = self.check_scam_patterns(sender, subject)
            if scam_check['scam_likely']:
                red_flags.extend(scam_check['red_flags'])

        # Check content preview for red flags (only for untrusted)
        if preview and not trusted:
            preview_lower = preview.lower()

            if 'click here' in preview_lower and ('verify' in preview_lower or 'confirm' in preview_lower):
                red_flags.append("Contains 'click here to verify' pattern")
            if 'act now' in preview_lower or 'act immediately' in preview_lower:
                red_flags.append("Urgency pressure: 'act now/immediately'")
            if 'social security' in preview_lower or 'ssn' in preview_lower:
                red_flags.append("Asks about SSN/Social Security")
            if re.search(r'password|credit card|bank account', preview_lower):
                red_flags.append("Asks for sensitive information")

        # Determine risk level
        if trusted and not red_flags:
            risk_level = RiskLevel.SAFE
            reasons = ["Sender is in trusted list"]
        elif len(red_flags) >= 2:
            risk_level = RiskLevel.LIKELY_SCAM
            reasons = red_flags
        elif len(red_flags) == 1:
            risk_level = RiskLevel.SUSPICIOUS
            reasons = red_flags
        elif not trusted:
            risk_level = RiskLevel.CAUTION
            reasons = ["Sender not in trusted list - verify if expected"]
        else:
            risk_level = RiskLevel.SAFE
            reasons = green_flags

        return EmailAnalysis(
            sender=sender,
            domain=domain,
            subject=subject,
            risk_level=risk_level,
            trusted=trusted,
            red_flags=red_flags,
            green_flags=green_flags,
            reasons=reasons
        )

    # Trust management
    def add_trusted_sender(self, email: str) -> bool:
        """Add email to trusted senders list."""
        self.trusted_senders.add(email.lower())
        self._save_rules()
        return True

    def add_trusted_domain(self, domain: str) -> bool:
        """Add domain to trusted domains list."""
        self.trusted_domains.add(domain.lower())
        self._save_rules()
        return True

    def block_domain(self, domain: str) -> bool:
        """Add domain to blocked list."""
        self.blocked_domains.add(domain.lower())
        self._save_rules()
        return True

    def remove_trusted_sender(self, email: str) -> bool:
        """Remove email from trusted senders."""
        self.trusted_senders.discard(email.lower())
        self._save_rules()
        return True

    def get_stats(self) -> dict:
        """Get current guardian statistics."""
        return {
            'trusted_senders': len(self.trusted_senders),
            'trusted_domains': len(self.trusted_domains),
            'blocked_domains': len(self.blocked_domains),
            'custom_rules': len(self.custom_rules)
        }


# Convenience function for quick analysis
def quick_analyze(sender: str, subject: str, preview: str = "") -> str:
    """Quick analysis returning emoji summary."""
    guardian = EmailGuardian()
    result = guardian.analyze(sender, subject, preview)
    return result.to_emoji_summary()


if __name__ == "__main__":
    # Demo
    guardian = EmailGuardian()

    print("=== Email Guardian Bot Demo ===\n")

    # Test scam
    result = guardian.analyze(
        "irs-refund@taxreturn.xyz",
        "Your IRS Tax Refund is Ready!"
    )
    print(result.to_emoji_summary())

    # Test legitimate
    result = guardian.analyze(
        "support@apple.com",
        "Your Apple ID was used to sign in"
    )
    print(result.to_emoji_summary())

# Email Guardian Bot

**AI-powered email security that protects you from scams, phishing, and fraud.**

A self-contained email security bot that analyzes incoming emails, detects threats, and sends real-time alerts via Telegram.

## Features

- **Real-time Scam Detection** - Pattern matching for phishing domains and suspicious subjects
- **Smart Risk Assessment** - 4-level risk scoring (Safe, Caution, Suspicious, Likely Scam)
- **Learning System** - Learns your trusted contacts over time
- **Telegram Alerts** - Instant notifications for threats
- **Multi-Provider Support** - Gmail, Outlook, Yahoo, iCloud, or any IMAP server
- **Zero Cloud Dependencies** - Runs 100% locally, your data stays private

## Quick Start

### 1. Install

```bash
git clone https://github.com/yourusername/email-guardian-bot
cd email-guardian-bot
pip install -r requirements.txt
```

### 2. Setup

```bash
python main.py --setup
```

Follow the wizard to configure:
- Telegram bot token (create via @BotFather)
- Your Telegram user ID
- Email credentials (optional, for auto-monitoring)

### 3. Run

```bash
python main.py
```

## Usage

### Telegram Commands

| Command | Description |
|---------|-------------|
| `/start` | Welcome message |
| `/status` | View protection stats |
| `/check <sender> <subject>` | Manually analyze an email |
| `/trust <email>` | Add sender to trusted list |
| `/block <domain>` | Block a domain |
| `/rules` | View current rules |

### Quick Check Mode

Analyze an email without running the full bot:

```bash
python main.py --check "irs@taxrefund.xyz" "Your refund is ready"
```

### Demo Mode

See the analyzer in action:

```bash
python main.py --demo
```

## Risk Levels

| Level | Emoji | Meaning |
|-------|-------|---------|
| Safe | ✅ | Trusted sender or domain |
| Caution | ⚠️ | Unknown sender - verify |
| Suspicious | 🚨 | One red flag detected |
| Likely Scam | ❌ | Multiple red flags - probable scam |

## What It Detects

### Domain Patterns
- Fake IRS/government domains (irs-refund.xyz)
- Typosquatting (paypa1.com, arnazon.com)
- Suspicious TLDs (.xyz, .info for financial emails)

### Subject Line Red Flags
- "Account suspended"
- "Urgent action required"
- "You've won"
- "Verify your identity"
- "Password expires"

### Content Red Flags
- Requests for passwords/SSN
- "Click here to verify"
- Urgency pressure tactics
- Generic greetings

## Configuration

Config is stored at `~/.email-guardian/config.json`:

```json
{
  "telegram_token": "your-bot-token",
  "telegram_admin_id": 123456789,
  "email_provider": "gmail",
  "email_address": "you@gmail.com",
  "email_password": "app-password",
  "alert_on_scam": true,
  "alert_on_suspicious": true,
  "alert_on_caution": false
}
```

### Gmail Setup

For Gmail, you need an **App Password**:
1. Go to https://myaccount.google.com/apppasswords
2. Create a new app password for "Mail"
3. Use that password in the setup wizard

## API Usage

Use the analyzer programmatically:

```python
from src import EmailGuardian

guardian = EmailGuardian()

# Analyze an email
result = guardian.analyze(
    sender="irs@taxrefund.xyz",
    subject="Your refund is ready",
    preview="Click here to claim..."
)

print(result.risk_level)  # RiskLevel.LIKELY_SCAM
print(result.red_flags)   # ['Suspicious domain pattern', ...]

# Manage trusted senders
guardian.add_trusted_sender("boss@mycompany.com")
guardian.block_domain("scammer.xyz")
```

## File Structure

```
email-guardian-bot/
├── main.py              # Entry point
├── requirements.txt     # Dependencies
├── src/
│   ├── __init__.py
│   ├── analyzer.py      # Core detection engine
│   ├── fetcher.py       # Email fetching (IMAP)
│   └── bot.py           # Telegram bot
└── config/
    └── rules.json       # Custom rules (auto-generated)
```

## License

MIT License - Use freely for personal or commercial purposes.

## Support

- Documentation: https://clientbuilder.pro/docs/email-guardian
- Issues: https://github.com/yourusername/email-guardian-bot/issues

---

Built with ❤️ by [ClientBuilder.pro](https://clientbuilder.pro)

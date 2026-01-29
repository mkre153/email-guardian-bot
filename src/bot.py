"""Email Guardian Bot - Telegram Bot Integration

Sends alerts and allows management via Telegram.
"""
import asyncio
import logging
from typing import Optional, Callable
from dataclasses import dataclass

# Optional imports - gracefully handle if not installed
try:
    from telegram import Update, Bot
    from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False
    Update = None
    Bot = None
    ContextTypes = None
    Application = None
    CommandHandler = None

from .analyzer import EmailGuardian, RiskLevel, EmailAnalysis
from .fetcher import EmailMessage


@dataclass
class BotConfig:
    token: str
    admin_chat_id: int
    alert_on_suspicious: bool = True
    alert_on_scam: bool = True
    alert_on_caution: bool = False
    daily_digest: bool = True
    digest_hour: int = 8


class EmailGuardianBot:
    """Telegram bot for email security alerts."""

    def __init__(self, config: BotConfig, guardian: Optional[EmailGuardian] = None):
        if not TELEGRAM_AVAILABLE:
            raise ImportError(
                "python-telegram-bot not installed. "
                "Run: pip install python-telegram-bot"
            )

        self.config = config
        self.guardian = guardian or EmailGuardian()
        self.app = None
        self.bot = None

        # Stats tracking
        self.stats = {
            'emails_analyzed': 0,
            'scams_blocked': 0,
            'suspicious_flagged': 0,
            'safe_passed': 0
        }

    async def start_command(self, update, context):
        """Handle /start command."""
        await update.message.reply_text(
            "🛡️ *Email Guardian Bot*\n\n"
            "I protect your inbox from scams and phishing.\n\n"
            "*Commands:*\n"
            "/status - View protection stats\n"
            "/trust <email> - Trust a sender\n"
            "/block <domain> - Block a domain\n"
            "/check <sender> <subject> - Analyze an email\n"
            "/rules - View current rules\n"
            "/help - Show this message",
            parse_mode='Markdown'
        )

    async def status_command(self, update, context):
        """Handle /status command."""
        guardian_stats = self.guardian.get_stats()

        message = (
            "📊 *Email Guardian Status*\n\n"
            f"*Session Stats:*\n"
            f"  📧 Emails analyzed: {self.stats['emails_analyzed']}\n"
            f"  ❌ Scams blocked: {self.stats['scams_blocked']}\n"
            f"  🚨 Suspicious flagged: {self.stats['suspicious_flagged']}\n"
            f"  ✅ Safe passed: {self.stats['safe_passed']}\n\n"
            f"*Rules:*\n"
            f"  👤 Trusted senders: {guardian_stats['trusted_senders']}\n"
            f"  🌐 Trusted domains: {guardian_stats['trusted_domains']}\n"
            f"  🚫 Blocked domains: {guardian_stats['blocked_domains']}\n"
        )

        await update.message.reply_text(message, parse_mode='Markdown')

    async def trust_command(self, update, context):
        """Handle /trust command."""
        if not context.args:
            await update.message.reply_text(
                "Usage: /trust <email@domain.com>\n"
                "Example: /trust support@mycompany.com"
            )
            return

        email = context.args[0].lower()
        if '@' not in email:
            await update.message.reply_text("❌ Invalid email address")
            return

        self.guardian.add_trusted_sender(email)
        await update.message.reply_text(f"✅ Added {email} to trusted senders")

    async def block_command(self, update, context):
        """Handle /block command."""
        if not context.args:
            await update.message.reply_text(
                "Usage: /block <domain.com>\n"
                "Example: /block scammer.xyz"
            )
            return

        domain = context.args[0].lower()
        self.guardian.block_domain(domain)
        await update.message.reply_text(f"🚫 Blocked domain: {domain}")

    async def check_command(self, update, context):
        """Handle /check command - manual email analysis."""
        if len(context.args) < 2:
            await update.message.reply_text(
                "Usage: /check <sender> <subject>\n"
                "Example: /check irs@taxrefund.xyz Your refund is ready"
            )
            return

        sender = context.args[0]
        subject = ' '.join(context.args[1:])

        result = self.guardian.analyze(sender, subject)
        await update.message.reply_text(
            result.to_emoji_summary(),
            parse_mode='Markdown'
        )

    async def rules_command(self, update, context):
        """Handle /rules command."""
        stats = self.guardian.get_stats()

        # Get some samples
        trusted = list(self.guardian.trusted_senders)[:5]
        blocked = list(self.guardian.blocked_domains)[:5]

        message = "📋 *Current Rules*\n\n"

        if trusted:
            message += "*Trusted Senders:*\n"
            for sender in trusted:
                message += f"  ✅ {sender}\n"
            if stats['trusted_senders'] > 5:
                message += f"  ... and {stats['trusted_senders'] - 5} more\n"
            message += "\n"

        if blocked:
            message += "*Blocked Domains:*\n"
            for domain in blocked:
                message += f"  🚫 {domain}\n"
            if stats['blocked_domains'] > 5:
                message += f"  ... and {stats['blocked_domains'] - 5} more\n"

        if not trusted and not blocked:
            message += "No custom rules configured yet.\n"
            message += "Use /trust and /block to add rules."

        await update.message.reply_text(message, parse_mode='Markdown')

    async def help_command(self, update, context):
        """Handle /help command."""
        await self.start_command(update, context)

    async def send_alert(self, analysis: EmailAnalysis, email_msg: Optional[EmailMessage] = None):
        """Send alert to admin chat."""
        if not self.bot:
            return

        # Determine if we should alert
        should_alert = False
        if analysis.risk_level == RiskLevel.LIKELY_SCAM and self.config.alert_on_scam:
            should_alert = True
        elif analysis.risk_level == RiskLevel.SUSPICIOUS and self.config.alert_on_suspicious:
            should_alert = True
        elif analysis.risk_level == RiskLevel.CAUTION and self.config.alert_on_caution:
            should_alert = True

        if not should_alert:
            return

        # Update stats
        self.stats['emails_analyzed'] += 1
        if analysis.risk_level == RiskLevel.LIKELY_SCAM:
            self.stats['scams_blocked'] += 1
        elif analysis.risk_level == RiskLevel.SUSPICIOUS:
            self.stats['suspicious_flagged'] += 1
        else:
            self.stats['safe_passed'] += 1

        # Build alert message
        alert = "🚨 *Email Security Alert*\n\n"
        alert += analysis.to_emoji_summary()

        if email_msg and email_msg.preview:
            alert += f"\n*Preview:* {email_msg.preview[:100]}..."

        alert += "\n\nReply with:\n"
        alert += f"/trust {analysis.sender} - Mark as safe\n"
        alert += f"/block {analysis.domain} - Block this domain"

        await self.bot.send_message(
            chat_id=self.config.admin_chat_id,
            text=alert,
            parse_mode='Markdown'
        )

    def analyze_and_alert(self, email_msg: EmailMessage) -> EmailAnalysis:
        """Analyze email and send alert if needed."""
        result = self.guardian.analyze(
            email_msg.sender,
            email_msg.subject,
            email_msg.preview
        )

        # Send alert asynchronously
        if self.bot:
            asyncio.create_task(self.send_alert(result, email_msg))

        return result

    def setup(self):
        """Setup the bot handlers."""
        self.app = Application.builder().token(self.config.token).build()
        self.bot = self.app.bot

        # Add handlers
        self.app.add_handler(CommandHandler("start", self.start_command))
        self.app.add_handler(CommandHandler("status", self.status_command))
        self.app.add_handler(CommandHandler("trust", self.trust_command))
        self.app.add_handler(CommandHandler("block", self.block_command))
        self.app.add_handler(CommandHandler("check", self.check_command))
        self.app.add_handler(CommandHandler("rules", self.rules_command))
        self.app.add_handler(CommandHandler("help", self.help_command))

    def run(self):
        """Run the bot (blocking)."""
        if not self.app:
            self.setup()

        print("🛡️ Email Guardian Bot starting...")
        self.app.run_polling(allowed_updates=Update.ALL_TYPES)


def create_bot(token: str, admin_chat_id: int, **kwargs) -> EmailGuardianBot:
    """Factory function to create configured bot."""
    config = BotConfig(token=token, admin_chat_id=admin_chat_id, **kwargs)
    return EmailGuardianBot(config)


if __name__ == "__main__":
    import os

    token = os.environ.get('TELEGRAM_BOT_TOKEN')
    admin_id = os.environ.get('TELEGRAM_ADMIN_ID')

    if not token or not admin_id:
        print("Set TELEGRAM_BOT_TOKEN and TELEGRAM_ADMIN_ID environment variables")
    else:
        bot = create_bot(token, int(admin_id))
        bot.run()

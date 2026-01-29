"""Email Guardian Bot - Protect your inbox from scams and phishing."""

__version__ = "1.0.0"
__author__ = "ClientBuilder.pro"

from .analyzer import EmailGuardian, EmailAnalysis, RiskLevel, quick_analyze
from .fetcher import EmailFetcher, EmailMessage, EmailWatcher

# Bot is optional (requires python-telegram-bot)
try:
    from .bot import EmailGuardianBot, BotConfig, create_bot
    BOT_AVAILABLE = True
except ImportError:
    EmailGuardianBot = None
    BotConfig = None
    create_bot = None
    BOT_AVAILABLE = False

__all__ = [
    'EmailGuardian',
    'EmailAnalysis',
    'RiskLevel',
    'quick_analyze',
    'EmailFetcher',
    'EmailMessage',
    'EmailWatcher',
    'EmailGuardianBot',
    'BotConfig',
    'create_bot',
    'BOT_AVAILABLE'
]

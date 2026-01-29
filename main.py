#!/usr/bin/env python3
"""Email Guardian Bot - Main Entry Point

Usage:
    python main.py                    # Run with config file
    python main.py --setup            # Interactive setup
    python main.py --check <email>    # Quick check mode
"""
import os
import sys
import json
import argparse
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.analyzer import EmailGuardian, quick_analyze
from src.fetcher import EmailFetcher, EmailWatcher
from src.bot import EmailGuardianBot, BotConfig


CONFIG_FILE = Path.home() / ".email-guardian" / "config.json"


def load_config() -> dict:
    """Load configuration from file."""
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text())
    return {}


def save_config(config: dict):
    """Save configuration to file."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def setup_wizard():
    """Interactive setup wizard."""
    print("🛡️  Email Guardian Bot Setup\n")

    config = load_config()

    # Telegram setup
    print("=== Telegram Bot Setup ===")
    print("Create a bot with @BotFather on Telegram to get a token.\n")

    token = input(f"Telegram Bot Token [{config.get('telegram_token', '')}]: ").strip()
    if token:
        config['telegram_token'] = token

    admin_id = input(f"Your Telegram User ID [{config.get('telegram_admin_id', '')}]: ").strip()
    if admin_id:
        config['telegram_admin_id'] = int(admin_id)

    # Email setup (optional)
    print("\n=== Email Setup (optional) ===")
    setup_email = input("Setup email monitoring? [y/N]: ").strip().lower()

    if setup_email == 'y':
        print("\nSupported providers: gmail, outlook, yahoo, icloud, custom")
        provider = input("Email provider [gmail]: ").strip() or 'gmail'
        config['email_provider'] = provider

        email_addr = input("Email address: ").strip()
        if email_addr:
            config['email_address'] = email_addr

        print("\nFor Gmail, create an App Password at https://myaccount.google.com/apppasswords")
        password = input("Email password/app password: ").strip()
        if password:
            config['email_password'] = password

    # Alert settings
    print("\n=== Alert Settings ===")
    config['alert_on_scam'] = input("Alert on likely scams? [Y/n]: ").strip().lower() != 'n'
    config['alert_on_suspicious'] = input("Alert on suspicious emails? [Y/n]: ").strip().lower() != 'n'
    config['alert_on_caution'] = input("Alert on unknown senders? [y/N]: ").strip().lower() == 'y'

    save_config(config)
    print(f"\n✅ Configuration saved to {CONFIG_FILE}")
    print("Run 'python main.py' to start the bot.")


def run_bot(config: dict):
    """Run the bot with monitoring."""
    if not config.get('telegram_token'):
        print("❌ Telegram token not configured. Run: python main.py --setup")
        sys.exit(1)

    # Create bot
    bot_config = BotConfig(
        token=config['telegram_token'],
        admin_chat_id=config.get('telegram_admin_id', 0),
        alert_on_scam=config.get('alert_on_scam', True),
        alert_on_suspicious=config.get('alert_on_suspicious', True),
        alert_on_caution=config.get('alert_on_caution', False)
    )

    bot = EmailGuardianBot(bot_config)

    # Setup email watcher if configured
    if config.get('email_address') and config.get('email_password'):
        fetcher = EmailFetcher(
            config['email_address'],
            config['email_password'],
            config.get('email_provider', 'gmail')
        )

        def on_new_email(email_msg):
            print(f"📧 New email: {email_msg.subject}")
            bot.analyze_and_alert(email_msg)

        watcher = EmailWatcher(fetcher, check_interval=60, callback=on_new_email)

        # Run watcher in background
        import threading
        watcher_thread = threading.Thread(target=watcher.start, daemon=True)
        watcher_thread.start()
        print("📧 Email monitoring active")

    # Run bot
    bot.run()


def quick_check(args):
    """Quick email check mode."""
    if len(args) < 2:
        print("Usage: python main.py --check <sender> <subject>")
        print("Example: python main.py --check irs@fake.com 'Your refund is ready'")
        sys.exit(1)

    sender = args[0]
    subject = ' '.join(args[1:])

    guardian = EmailGuardian()
    result = guardian.analyze(sender, subject)
    print(result.to_emoji_summary())


def main():
    parser = argparse.ArgumentParser(description='Email Guardian Bot')
    parser.add_argument('--setup', action='store_true', help='Run setup wizard')
    parser.add_argument('--check', nargs='*', help='Quick check mode: --check <sender> <subject>')
    parser.add_argument('--demo', action='store_true', help='Run demo analysis')

    args = parser.parse_args()

    if args.setup:
        setup_wizard()
    elif args.check:
        quick_check(args.check)
    elif args.demo:
        print("🛡️  Email Guardian Bot Demo\n")
        guardian = EmailGuardian()

        tests = [
            ("irs-refund@taxreturn.xyz", "Your IRS Tax Refund is Ready!"),
            ("support@apple.com", "Your Apple ID was used to sign in"),
            ("prince@nigeria.co", "You've Won $10,000,000!"),
            ("hr@yourcompany.com", "Updated PTO Policy"),
        ]

        for sender, subject in tests:
            result = guardian.analyze(sender, subject)
            print(result.to_emoji_summary())
            print("-" * 40)
    else:
        config = load_config()
        if not config:
            print("No configuration found. Run: python main.py --setup")
            sys.exit(1)
        run_bot(config)


if __name__ == "__main__":
    main()

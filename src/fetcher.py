"""Email Guardian Bot - Email Fetcher

Multi-provider email fetching with support for:
- Gmail (via API or IMAP)
- Outlook/Office 365
- Generic IMAP
"""
import imaplib
import email
from email.header import decode_header
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from dataclasses import dataclass
import json
from pathlib import Path


@dataclass
class EmailMessage:
    id: str
    sender: str
    subject: str
    date: str
    preview: str
    folder: str
    read: bool

    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'sender': self.sender,
            'subject': self.subject,
            'date': self.date,
            'preview': self.preview,
            'folder': self.folder,
            'read': self.read
        }


class EmailFetcher:
    """Generic IMAP email fetcher."""

    # Provider presets
    PROVIDERS = {
        'gmail': {
            'host': 'imap.gmail.com',
            'port': 993,
            'ssl': True
        },
        'outlook': {
            'host': 'outlook.office365.com',
            'port': 993,
            'ssl': True
        },
        'yahoo': {
            'host': 'imap.mail.yahoo.com',
            'port': 993,
            'ssl': True
        },
        'icloud': {
            'host': 'imap.mail.me.com',
            'port': 993,
            'ssl': True
        }
    }

    def __init__(
        self,
        email_address: str,
        password: str,
        provider: str = 'gmail',
        host: Optional[str] = None,
        port: Optional[int] = None
    ):
        self.email_address = email_address
        self.password = password

        if provider in self.PROVIDERS:
            config = self.PROVIDERS[provider]
            self.host = host or config['host']
            self.port = port or config['port']
        else:
            if not host or not port:
                raise ValueError(f"Unknown provider '{provider}'. Provide host and port.")
            self.host = host
            self.port = port

        self.connection: Optional[imaplib.IMAP4_SSL] = None

    def connect(self) -> bool:
        """Connect to IMAP server."""
        try:
            self.connection = imaplib.IMAP4_SSL(self.host, self.port)
            self.connection.login(self.email_address, self.password)
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    def disconnect(self):
        """Disconnect from IMAP server."""
        if self.connection:
            try:
                self.connection.logout()
            except:
                pass
            self.connection = None

    def _decode_header_value(self, value: str) -> str:
        """Decode email header value."""
        if not value:
            return ""

        decoded_parts = decode_header(value)
        result = []
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                try:
                    result.append(part.decode(encoding or 'utf-8', errors='replace'))
                except:
                    result.append(part.decode('utf-8', errors='replace'))
            else:
                result.append(part)
        return ' '.join(result)

    def _get_preview(self, msg) -> str:
        """Extract text preview from email."""
        preview = ""

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            preview = payload.decode('utf-8', errors='replace')[:200]
                            break
                    except:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    preview = payload.decode('utf-8', errors='replace')[:200]
            except:
                pass

        return preview.strip().replace('\n', ' ').replace('\r', '')

    def fetch_emails(
        self,
        folder: str = "INBOX",
        limit: int = 20,
        unread_only: bool = False,
        since_days: Optional[int] = None
    ) -> List[EmailMessage]:
        """
        Fetch emails from specified folder.

        Args:
            folder: IMAP folder name
            limit: Maximum emails to fetch
            unread_only: Only fetch unread emails
            since_days: Only fetch emails from last N days

        Returns:
            List of EmailMessage objects
        """
        if not self.connection:
            if not self.connect():
                return []

        try:
            self.connection.select(folder)

            # Build search criteria
            criteria = []
            if unread_only:
                criteria.append('UNSEEN')
            if since_days:
                since_date = (datetime.now() - timedelta(days=since_days)).strftime("%d-%b-%Y")
                criteria.append(f'SINCE {since_date}')

            search_criteria = ' '.join(criteria) if criteria else 'ALL'

            _, message_numbers = self.connection.search(None, search_criteria)

            emails = []
            msg_nums = message_numbers[0].split()

            # Get most recent first
            for num in reversed(msg_nums[-limit:]):
                _, msg_data = self.connection.fetch(num, '(RFC822 FLAGS)')

                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])

                        # Check if read
                        flags_data = msg_data[1] if len(msg_data) > 1 else b''
                        is_read = b'\\Seen' in flags_data if isinstance(flags_data, bytes) else False

                        emails.append(EmailMessage(
                            id=num.decode(),
                            sender=self._decode_header_value(msg.get('From', '')),
                            subject=self._decode_header_value(msg.get('Subject', '')),
                            date=msg.get('Date', ''),
                            preview=self._get_preview(msg),
                            folder=folder,
                            read=is_read
                        ))

            return emails

        except Exception as e:
            print(f"Fetch error: {e}")
            return []

    def get_folders(self) -> List[str]:
        """Get list of available folders."""
        if not self.connection:
            if not self.connect():
                return []

        try:
            _, folders = self.connection.list()
            folder_names = []
            for folder in folders:
                # Parse folder response
                parts = folder.decode().split(' "/" ')
                if len(parts) > 1:
                    folder_names.append(parts[1].strip('"'))
            return folder_names
        except Exception as e:
            print(f"Error getting folders: {e}")
            return []

    def mark_read(self, email_id: str, folder: str = "INBOX") -> bool:
        """Mark an email as read."""
        if not self.connection:
            return False

        try:
            self.connection.select(folder)
            self.connection.store(email_id.encode(), '+FLAGS', '\\Seen')
            return True
        except:
            return False

    def move_to_spam(self, email_id: str, folder: str = "INBOX") -> bool:
        """Move email to spam folder."""
        if not self.connection:
            return False

        try:
            self.connection.select(folder)
            # Copy to spam, then delete from inbox
            self.connection.copy(email_id.encode(), '[Gmail]/Spam')
            self.connection.store(email_id.encode(), '+FLAGS', '\\Deleted')
            self.connection.expunge()
            return True
        except Exception as e:
            print(f"Error moving to spam: {e}")
            return False


class EmailWatcher:
    """Watch for new emails and trigger analysis."""

    def __init__(
        self,
        fetcher: EmailFetcher,
        check_interval: int = 60,
        callback=None
    ):
        self.fetcher = fetcher
        self.check_interval = check_interval
        self.callback = callback
        self.seen_ids: set = set()
        self.running = False

    def check_new(self) -> List[EmailMessage]:
        """Check for new emails since last check."""
        emails = self.fetcher.fetch_emails(unread_only=True, limit=50)
        new_emails = []

        for email_msg in emails:
            if email_msg.id not in self.seen_ids:
                self.seen_ids.add(email_msg.id)
                new_emails.append(email_msg)

                if self.callback:
                    self.callback(email_msg)

        return new_emails

    def start(self):
        """Start watching (blocking)."""
        import time
        self.running = True

        while self.running:
            self.check_new()
            time.sleep(self.check_interval)

    def stop(self):
        """Stop watching."""
        self.running = False


if __name__ == "__main__":
    print("Email Fetcher - requires credentials to test")
    print("Usage:")
    print("  fetcher = EmailFetcher('user@gmail.com', 'app-password', 'gmail')")
    print("  emails = fetcher.fetch_emails(limit=5)")

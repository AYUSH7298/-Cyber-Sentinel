from sqlalchemy.orm import Session
from backend import models
from backend.config import settings
import asyncio
import hashlib
import logging

logger = logging.getLogger(__name__)

try:
    from telethon import TelegramClient
    from telethon.errors import (
        FloodWaitError,
        UsernameNotOccupiedError,
        ChannelPrivateError,
        SessionPasswordNeededError,
    )
    _TELETHON_AVAILABLE = True
except ImportError:
    _TELETHON_AVAILABLE = False
    TelegramClient = None  # type: ignore[assignment,misc]
    logger.warning(
        "[Telethon] telethon library not installed. "
        "Telegram collection will be disabled. Install with: pip install telethon"
    )


class TelegramCollector:
    """
    Collects public messages from Telegram channels using the Telethon MTProto client.

    LEGAL NOTE: Only public channels are accessed. No private messages or groups
    are scraped. All data collection is performed within Telegram's Terms of Service
    for public content. API credentials must be obtained from https://my.telegram.org
    """

    def __init__(self):
        self.api_id = settings.TELEGRAM_API_ID
        self.api_hash = settings.TELEGRAM_API_HASH
        self.session_name = settings.TELEGRAM_SESSION_NAME
        self.channels = settings.telegram_channels_list
        self.messages_per_channel = 1500   # Scaled to pull ~15k records total across channels

    async def fetch_latest_messages_async(self, db: Session) -> int:
        """
        Asynchronously scrape public Telegram channels and store new messages.

        Returns the count of newly ingested messages.
        """
        if not _TELETHON_AVAILABLE:
            logger.warning("[Telethon] telethon not installed. Skipping Telegram collection.")
            return 0

        if not settings.is_telegram_configured:
            logger.warning(
                "[Telethon] Credentials not configured (TG_API_ID / TG_API_HASH). "
                "Set them in .env to enable live Telegram collection."
            )
            return 0

        total_count = 0
        client = TelegramClient(self.session_name, self.api_id, self.api_hash)

        try:
            await client.connect()

            if not await client.is_user_authorized():
                logger.error(
                    "[Telethon] Session '%s' is not authorized. "
                    "Run: python -c \"from backend.collectors.telegram_osint import *; "
                    "import asyncio; asyncio.run(authorize_session())\" to authorize.",
                    self.session_name,
                )
                return 0

            for channel_username in self.channels:
                count = await self._scrape_channel(client, channel_username, db)
                total_count += count
                # Brief rate-limit pause between channels
                await asyncio.sleep(1)

            db.commit()
            logger.info("[Telethon] Total new messages ingested: %d", total_count)

        except FloodWaitError as exc:
            logger.warning("[Telethon] Rate limited. Retry after %d seconds.", exc.seconds)
        except SessionPasswordNeededError:
            logger.error("[Telethon] 2FA is enabled. Please add your password to the session.")
        except Exception as exc:
            logger.error("[Telethon] Unexpected error: %s", exc)
        finally:
            await client.disconnect()

        return total_count

    async def _scrape_channel(
        self, client: TelegramClient, channel_username: str, db: Session
    ) -> int:
        """Scrape a single public Telegram channel for recent messages."""
        count = 0
        try:
            entity = await client.get_entity(channel_username)
            messages = await client.get_messages(entity, limit=self.messages_per_channel)

            for msg in messages:
                if not msg or not msg.text:
                    continue
                text = msg.text.strip()
                if len(text) < 20:
                    continue

                # O(1) dedup via SHA-256 content_hash index
                content_hash = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
                exists = (
                    db.query(models.RawIntel)
                    .filter(models.RawIntel.content_hash == content_hash)
                    .first()
                )
                if not exists:
                    is_hindi = any(0x0900 < ord(c) < 0x097F for c in text)
                    db.add(models.RawIntel(
                        source=f"telegram:{channel_username}",
                        raw_text=text,
                        content_hash=content_hash,
                        source_url=f"https://t.me/{channel_username}",
                        language="hi" if is_hindi else "en",
                    ))
                    count += 1

            logger.info("[Telethon] Channel @%s → %d new messages", channel_username, count)

        except ChannelPrivateError:
            logger.warning("[Telethon] @%s is private. Skipping.", channel_username)
        except UsernameNotOccupiedError:
            logger.warning("[Telethon] @%s does not exist.", channel_username)
        except FloodWaitError as exc:
            logger.warning("[Telethon] Flood wait on @%s: %ds", channel_username, exc.seconds)
        except Exception as exc:
            logger.error("[Telethon] Error on @%s: %s", channel_username, exc)

        return count


async def authorize_session():
    """
    One-time interactive session authorization helper.
    Run this once from the command line to create the Telethon session file.

    Usage:
        python -c "import asyncio; from backend.collectors.telegram_osint import authorize_session; asyncio.run(authorize_session())"
    """
    client = TelegramClient(
        settings.TELEGRAM_SESSION_NAME,
        settings.TELEGRAM_API_ID,
        settings.TELEGRAM_API_HASH,
    )
    await client.start()
    print("[✓] Telethon session authorized and saved.")
    await client.disconnect()

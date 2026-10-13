"""Container entry point for applying database migrations before the API starts."""

from __future__ import annotations

import asyncio

from app.migrations import migrate_database

if __name__ == "__main__":
    asyncio.run(migrate_database())

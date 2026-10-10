"""Worker main entry point."""
import asyncio
from app.workers.scan_worker import main

if __name__ == "__main__":
    asyncio.run(main())

"""Single-worker lifecycle: lock control state, recover owned containers, reap idle sessions."""

import asyncio
import logging
import os

from tools.sandbox import local_service

logger = logging.getLogger(__name__)
_task = None


async def start():
    global _task
    if _task and not _task.done():
        return
    service = local_service.get_local_service()
    service._recovery_pending = True
    try:
        await asyncio.to_thread(service.recover)
        service._recovery_pending = False
    except Exception:
        logger.warning(
            "Sandbox recovery pending; cleanup will retry when the backend is available",
            exc_info=True,
        )

    async def reap():
        while True:
            await asyncio.sleep(10)
            try:
                if service._recovery_pending:
                    await asyncio.to_thread(service.recover)
                    service._recovery_pending = False
                else:
                    await asyncio.to_thread(service.cleanup)
            except Exception:
                logger.exception("Sandbox cleanup will retry")

    _task = asyncio.create_task(reap(), name="weaver-sandbox-cleanup")


async def shutdown():
    global _task
    if _task:
        _task.cancel()
        try:
            await _task
        except asyncio.CancelledError:
            pass
        _task = None
    service = local_service._service
    if service:
        await asyncio.to_thread(service.cleanup, all_sessions=True)
        descriptor = getattr(service, "_process_lock", None)
        if descriptor is not None:
            os.close(descriptor)
            service._process_lock = None
        local_service._service = None

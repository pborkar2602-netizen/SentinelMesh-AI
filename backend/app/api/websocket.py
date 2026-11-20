import json
import asyncio
import logging
from typing import Optional, Set
from fastapi import WebSocket

logger = logging.getLogger(__name__)

class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    async def connect(self, websocket: WebSocket) -> None:
        self._loop = asyncio.get_running_loop()
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"WebSocket client connected. Total clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections.discard(websocket)
        logger.info(f"WebSocket client disconnected. Total clients: {len(self.active_connections)}")

    async def broadcast(self, data: dict) -> None:
        if not self.active_connections:
            return

        payload = json.dumps(data, default=str)
        dead_connections = set()

        for connection in list(self.active_connections):
            try:
                await connection.send_text(payload)
            except Exception as e:
                logger.warning(f"Failed to send to WebSocket client: {e}")
                dead_connections.add(connection)

        for dead in dead_connections:
            self.active_connections.discard(dead)

    def broadcast_sync(self, data: dict) -> None:
        """
        Synchronous helper to broadcast from synchronous endpoint handlers (worker threads).
        """
        if not self.active_connections:
            return
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.broadcast(data))
        except RuntimeError:
            if self._loop is not None and not self._loop.is_closed() and self._loop.is_running():
                asyncio.run_coroutine_threadsafe(self.broadcast(data), self._loop)

ws_manager = ConnectionManager()

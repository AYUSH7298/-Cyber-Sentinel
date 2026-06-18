from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import List
import json
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

class ConnectionManager:
    """
    Manages active WebSocket connections for real-time dashboard auto-refresh.
    """
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"New WebSocket connection. Total active: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket disconnected. Total active: {len(self.active_connections)}")

    async def broadcast_threat(self, threat_data: dict):
        """
        Instantly pushes a newly detected threat to all connected React dashboards.
        """
        message = json.dumps(threat_data)
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error(f"Failed to send WebSocket message: {e}")
                self.disconnect(connection)

# Global manager instance
manager = ConnectionManager()

@router.websocket("/ws/live-feed")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            data = await websocket.receive_text()
            # We don't expect the client to send much data, but we can echo or handle ping/pong here
    except WebSocketDisconnect:
        manager.disconnect(websocket)

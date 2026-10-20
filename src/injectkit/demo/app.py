"""FastAPI app for the intentionally vulnerable demo target (extra: ``injectkit[demo]``)."""

from __future__ import annotations

from typing import Annotated

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from injectkit.demo.backends import Backend, BackendUnavailableError

MAX_BODY_BYTES = 16 * 1024
MAX_MESSAGES = 20


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str = Field(max_length=32)
    content: str


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    messages: Annotated[list[ChatMessage], Field(min_length=1, max_length=MAX_MESSAGES)]


class ChatResponse(BaseModel):
    reply: str


async def _bounded_body(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise HTTPException(status_code=413, detail="request body too large")
    received = bytearray()
    async for chunk in request.stream():
        received.extend(chunk)
        if len(received) > limit:
            raise HTTPException(status_code=413, detail="request body too large")
    return bytes(received)


def create_app(backend: Backend, *, max_body_bytes: int = MAX_BODY_BYTES) -> FastAPI:
    """Build the app around one backend. ``POST /chat`` answers ``{"reply": "..."}``."""
    app = FastAPI(
        title="InjectKit vulnerable demo",
        description="Intentionally vulnerable. Loopback only. Fake secrets only.",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "backend": backend.name}

    @app.post("/chat")
    async def chat(request: Request) -> ChatResponse:
        raw = await _bounded_body(request, max_body_bytes)
        try:
            body = ChatRequest.model_validate_json(raw)
        except ValueError:
            raise HTTPException(status_code=422, detail="invalid chat request") from None
        user_turns = [m.content for m in body.messages if m.role == "user"]
        if not user_turns:
            raise HTTPException(status_code=422, detail="no user message")
        try:
            return ChatResponse(reply=await backend.reply(user_turns[-1]))
        except BackendUnavailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from None

    return app

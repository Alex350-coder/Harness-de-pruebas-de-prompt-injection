import httpx
import pytest
import respx

import injectkit


def test_package_exposes_version() -> None:
    assert injectkit.__version__


async def test_respx_intercepts_httpx_async_client() -> None:
    """R1: the resolved respx/httpx pair must work together."""
    with respx.mock(base_url="https://example.test") as router:
        router.get("/ping").respond(200, json={"ok": True})
        async with httpx.AsyncClient(base_url="https://example.test") as client:
            response = await client.get("/ping")
    assert response.json() == {"ok": True}


def test_version_falls_back_to_a_visible_marker_when_metadata_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib
    import importlib.metadata

    import injectkit

    def missing(_name: str) -> str:
        raise importlib.metadata.PackageNotFoundError

    monkeypatch.setattr(importlib.metadata, "version", missing)
    try:
        reloaded = importlib.reload(injectkit)
        assert reloaded.__version__ == "0+unknown"
    finally:
        monkeypatch.undo()
        importlib.reload(injectkit)

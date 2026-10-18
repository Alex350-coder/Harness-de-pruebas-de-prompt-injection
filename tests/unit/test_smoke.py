import httpx
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

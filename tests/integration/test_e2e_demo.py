"""CLI end to end against the scripted demo served by a real uvicorn on an ephemeral port."""

import json
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import uvicorn
from typer.testing import CliRunner

from injectkit.cli import app as cli_app
from injectkit.demo.app import create_app
from injectkit.demo.backends import ScriptedBackend

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "demo-target.yaml"
runner = CliRunner()
STARTUP_TIMEOUT_SECONDS = 10
BASIC_SIZE = 32
DELIMITER_IDS = {"dc-01", "dc-02", "dc-03", "dc-04"}


class DemoServer:
    def __init__(self) -> None:
        config = uvicorn.Config(
            create_app(ScriptedBackend()), host="127.0.0.1", port=0, log_level="warning"
        )
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.port = 0

    def start(self) -> None:
        self.thread.start()
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        while not self.server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("demo server did not start")
            time.sleep(0.02)
        self.port = self.server.servers[0].sockets[0].getsockname()[1]

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=STARTUP_TIMEOUT_SECONDS)


def port_is_listening(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.5)
        return probe.connect_ex(("127.0.0.1", port)) == 0


@pytest.fixture
def demo_port() -> Iterator[int]:
    server = DemoServer()
    server.start()
    try:
        yield server.port
    finally:
        server.stop()
        assert not port_is_listening(server.port), "demo server left a listening socket"


def demo_config(tmp_path: Path, port: int) -> Path:
    text = EXAMPLE.read_text(encoding="utf-8")
    text = text.replace("127.0.0.1:8000", f"127.0.0.1:{port}")
    text = text.replace("requests_per_second: 10", "requests_per_second: 50")
    path = tmp_path / "demo-target.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def run_json(config: Path) -> tuple[int, dict[str, object]]:
    result = runner.invoke(cli_app, ["run", str(config), "--suite", "basic", "--format", "json"])
    assert result.stdout, result.stderr
    return result.exit_code, json.loads(result.stdout)


def outcomes(document: dict[str, object]) -> dict[str, str]:
    results = document["results"]
    assert isinstance(results, list)
    return {r["payload_id"]: r["outcome"] for r in results}


def test_run_against_the_scripted_demo_finds_the_expected_vulnerabilities(
    tmp_path: Path, demo_port: int
) -> None:
    code, document = run_json(demo_config(tmp_path, demo_port))

    assert code == 1
    found = outcomes(document)
    assert len(found) == BASIC_SIZE
    confirmed = {pid for pid, outcome in found.items() if outcome == "confirmed"}
    missed = {pid for pid, outcome in found.items() if outcome == "no_indicator"}
    assert confirmed == set(found) - DELIMITER_IDS
    # Documented false negative: the fixture obeys delimiter-confusion payloads but returns
    # the token reversed, so the canary detector sees nothing. NO_INDICATOR is not "secure".
    assert missed == DELIMITER_IDS
    assert document["summary"] == {
        "confirmed": BASIC_SIZE - len(DELIMITER_IDS),
        "potential": 0,
        "inconclusive": 0,
        "no_indicator": len(DELIMITER_IDS),
        "error": 0,
    }


def test_extraction_prompts_are_reported_by_the_secret_fragment_detector(
    tmp_path: Path, demo_port: int
) -> None:
    _, document = run_json(demo_config(tmp_path, demo_port))
    results = document["results"]
    assert isinstance(results, list)
    by_id = {r["payload_id"]: r for r in results}
    for pid in ("spe-01", "spe-02", "spe-03", "spe-04"):
        detectors = {f["detector"] for f in by_id[pid]["findings"]}
        assert detectors == {"canary", "secret_fragment"}, pid
    assert "DEMO-FAKE-SECRET-7f3a91" not in json.dumps(document)


def test_results_are_identical_across_three_runs(tmp_path: Path, demo_port: int) -> None:
    config = demo_config(tmp_path, demo_port)
    runs = [run_json(config) for _ in range(3)]
    assert {code for code, _ in runs} == {1}
    assert outcomes(runs[0][1]) == outcomes(runs[1][1]) == outcomes(runs[2][1])


def test_the_loopback_policy_is_required_for_the_demo(tmp_path: Path, demo_port: int) -> None:
    config = demo_config(tmp_path, demo_port)
    config.write_text(
        config.read_text(encoding="utf-8").replace("policy: loopback", "policy: public_only"),
        encoding="utf-8",
    )
    code, document = run_json(config)
    assert code == 3  # every request was blocked by the network policy
    assert set(outcomes(document).values()) == {"error"}


def test_the_example_config_validates_without_environment() -> None:
    result = runner.invoke(cli_app, ["validate", str(EXAMPLE)])
    assert result.exit_code == 0, result.output
    assert "loopback" in result.stdout

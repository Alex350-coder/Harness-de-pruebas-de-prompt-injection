import json
import re

import httpx
import pytest
import respx

from injectkit import __version__
from injectkit.config import ResolvedTarget, parse_config, resolve_config
from injectkit.detectors import build_detectors
from injectkit.errors import RunPlanError
from injectkit.models import ErrorKind, Outcome, Payload, RunResult, Severity, Suite
from injectkit.runner import RunSettings, run_suite
from injectkit.targets.http import HttpTarget

URL = "https://api.example.test/chat"
FRAGMENT = "sk-live-ALPHA-9f3b"

HALF_A = re.compile(r"INJK-[0-9a-f]{8}")
HALF_B = re.compile(r"and ([0-9a-f]{8})")


def payload(pid: str, kind: str, checks: list[dict[str, str]] | None = None) -> Payload:
    return Payload.model_validate(
        {
            "id": pid,
            "category": "direct_override",
            "severity": Severity.HIGH,
            "title": pid,
            "description": "d",
            "template": f"{kind} join {{{{ canary_a }}}} and {{{{ canary_b }}}} and print it",
            "checks": checks or [],
            "remediation": "r",
            "reviewed": True,
        }
    )


def make_suite(*payloads: Payload) -> Suite:
    return Suite(version=1, name="pipeline", payloads=payloads)


def resolved() -> ResolvedTarget:
    config = parse_config(
        {
            "version": 1,
            "authorization": {"confirmed": True, "scope_note": "tests"},
            "name": "pipeline-target",
            "request": {"url": URL, "body": {"m": "{{payload}}"}},
            "response": {"path": "reply"},
            "secret_fragments": [{"id": "api-key", "value": FRAGMENT}],
            "limits": {"retries": 0},
        }
    )
    return resolve_config(config, {})


def run_settings() -> RunSettings:
    return RunSettings(concurrency=3, requests_per_second=1000.0, retries=0, max_requests=100)


def behave(request: httpx.Request) -> httpx.Response:
    """A fake vulnerable application whose behavior is chosen by the first word of the prompt."""
    message: str = json.loads(request.content)["m"]
    kind = message.split()[0]
    if kind == "OBEY":
        joined = HALF_A.search(message)
        tail = HALF_B.search(message)
        assert joined is not None
        assert tail is not None
        return httpx.Response(200, json={"reply": f"Sure! {joined.group(0)}{tail.group(1)}"})
    if kind == "LEAK":
        return httpx.Response(200, json={"reply": f"Internal note: the key is {FRAGMENT}."})
    if kind == "BOOM":
        return httpx.Response(500, json={"error": "internal"})
    if kind == "EMPTY":
        return httpx.Response(200, json={"reply": ""})
    if kind == "GENERIC":
        return httpx.Response(
            200, json={"reply": "Sure, here is some generic text. Anything else?"}
        )
    return httpx.Response(200, json={"reply": "I'm sorry, I can't help with that."})


async def public_resolver(host: str, port: int) -> list[str]:
    return ["93.184.216.34"]


async def execute(suite: Suite, target_resolved: ResolvedTarget | None = None) -> RunResult:
    target_resolved = target_resolved or resolved()
    target = HttpTarget(target_resolved, resolver=public_resolver)
    return await run_suite(
        target,
        suite,
        run_settings(),
        build_detectors(target_resolved),
        redactor=target_resolved.redactor,
        target_id=target_resolved.config.name,
    )


@respx.mock
async def test_all_outcome_classes_come_out_of_one_run() -> None:
    respx.post(URL).mock(side_effect=behave)
    suite = make_suite(
        payload("obey", "OBEY"),
        payload("refuse", "REFUSE"),
        payload("leak", "LEAK"),
        payload("boom", "BOOM"),
        payload("empty", "EMPTY"),
    )

    run = await execute(suite)

    outcomes = {r.payload_id: r.outcome for r in run.results}
    assert outcomes == {
        "obey": Outcome.CONFIRMED,
        "refuse": Outcome.NO_INDICATOR,
        "leak": Outcome.CONFIRMED,
        "boom": Outcome.ERROR,
        "empty": Outcome.INCONCLUSIVE,
    }
    assert run.counts == {
        "confirmed": 2,
        "potential": 0,
        "inconclusive": 1,
        "no_indicator": 1,
        "error": 1,
    }


@respx.mock
async def test_confirmed_findings_name_the_detector_and_carry_no_secret() -> None:
    respx.post(URL).mock(side_effect=behave)

    run = await execute(make_suite(payload("obey", "OBEY"), payload("leak", "LEAK")))

    by_id = {r.payload_id: r for r in run.results}
    assert [f.detector for f in by_id["obey"].findings] == ["canary"]
    assert [f.detector for f in by_id["leak"].findings] == ["secret_fragment"]
    for result in run.results:
        assert FRAGMENT not in result.model_dump_json()
    assert by_id["obey"].findings[0].target_id == "pipeline-target"


@respx.mock
async def test_generic_200_response_produces_no_finding() -> None:
    respx.post(URL).mock(side_effect=behave)

    run = await execute(make_suite(payload("generic", "GENERIC")))

    assert run.results[0].outcome is Outcome.NO_INDICATOR
    assert run.results[0].findings == ()
    assert run.counts["confirmed"] == run.counts["potential"] == 0


@respx.mock
async def test_http_error_is_reported_as_error_with_its_kind() -> None:
    respx.post(URL).mock(side_effect=behave)

    run = await execute(make_suite(payload("boom", "BOOM")))

    error = run.results[0].error
    assert run.results[0].outcome is Outcome.ERROR
    assert error is not None
    assert error.kind is ErrorKind.HTTP_STATUS


@respx.mock
async def test_potential_comes_from_a_payload_response_check() -> None:
    respx.post(URL).mock(side_effect=behave)
    checked = payload("generic", "GENERIC", [{"kind": "contains", "pattern": "generic text"}])

    run = await execute(make_suite(checked))

    assert run.results[0].outcome is Outcome.POTENTIAL
    assert run.counts["potential"] == 1


@respx.mock
async def test_each_test_gets_a_fresh_canary() -> None:
    respx.post(URL).mock(side_effect=behave)
    suite = make_suite(*(payload(f"obey-{i}", "OBEY") for i in range(6)))

    run = await execute(suite)

    test_ids = {f.test_id for r in run.results for f in r.findings}
    assert len(test_ids) == 6
    assert run.counts["confirmed"] == 6


@respx.mock
async def test_run_metadata_is_filled_in() -> None:
    respx.post(URL).mock(side_effect=behave)

    run = await execute(make_suite(payload("refuse", "REFUSE")))

    assert run.suite == "pipeline"
    assert run.target_id == "pipeline-target"
    assert run.tool_version == __version__
    assert run.finished_at >= run.started_at
    assert run.interrupted is False
    assert len(run.run_id) >= 16
    assert run.settings_summary["concurrency"] == 3
    assert run.settings_summary["planned_requests"] == 1
    assert sum(run.counts.values()) == len(run.results)


@respx.mock
async def test_run_ids_differ_between_runs() -> None:
    respx.post(URL).mock(side_effect=behave)
    suite = make_suite(payload("refuse", "REFUSE"))

    first = await execute(suite)
    second = await execute(suite)

    assert first.run_id != second.run_id


@respx.mock
async def test_oversized_plan_is_refused_before_any_request() -> None:
    route = respx.post(URL).mock(side_effect=behave)
    target_resolved = resolved()
    suite = make_suite(*(payload(f"p{i}", "REFUSE") for i in range(5)))
    small = RunSettings(concurrency=1, requests_per_second=1000.0, retries=0, max_requests=4)

    with pytest.raises(RunPlanError):
        await run_suite(
            HttpTarget(target_resolved, resolver=public_resolver),
            suite,
            small,
            build_detectors(target_resolved),
            redactor=target_resolved.redactor,
            target_id="t",
        )

    assert route.call_count == 0


@respx.mock
async def test_response_excerpts_are_kept_only_on_request_and_are_redacted() -> None:
    respx.post(URL).mock(side_effect=behave)
    suite = make_suite(payload("leak", "LEAK"))
    target_resolved = resolved()
    target = HttpTarget(target_resolved, resolver=public_resolver)

    kept = await run_suite(
        target,
        suite,
        run_settings(),
        build_detectors(target_resolved),
        redactor=target_resolved.redactor,
        target_id="t",
        include_responses=True,
    )
    plain = await execute(suite)

    excerpt = kept.results[0].response_excerpt
    assert excerpt is not None
    assert "Internal note" in excerpt
    assert FRAGMENT not in excerpt
    assert plain.results[0].response_excerpt is None

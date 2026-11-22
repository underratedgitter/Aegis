"""The investigator is bounded in time, rounds and prompt size, and always falls back."""

import json
from types import SimpleNamespace
from typing import ClassVar

import pytest

from aegis import agent as agent_module
from aegis.agent import AgentInvestigator
from aegis.settings import Settings
from aegis.storage import Store

VALID_ANSWER = {
    "hypothesis": "inventory is down",
    "confidence": "high",
    "evidence": [{"source": "prometheus", "label": "errors", "detail": "1.0"}],
    "recommendation": {
        "action": "clear_fault",
        "target": "inventory",
        "parameters": {"fault": "dependency"},
        "reason": "known fault",
    },
    "next_checks": [],
}


class FakeTelemetry:
    def __init__(self):
        self.on_logs = None
        self.log_message = "dependency_failure"

    def metric_snapshot(self):
        return []

    def recent_logs(self, service=None, limit=30):
        if self.on_logs:
            self.on_logs()
        return [{"message": self.log_message, "service": "checkout"}]

    def prometheus_query(self, query):
        return {"query": query, "value": 1.0}


def _tool_call(name="get_recent_logs", arguments="{}", call_id="call-1"):
    call = SimpleNamespace(
        id=call_id, function=SimpleNamespace(name=name, arguments=arguments)
    )
    call.model_dump = lambda: {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": arguments},
    }
    return call


def _response(content=None, tool_calls=None):
    message = SimpleNamespace(content=content, tool_calls=tool_calls)
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


class FakeOpenAI:
    """Replays scripted responses; a scripted exception is raised instead."""

    script: ClassVar[list] = []
    init_kwargs: ClassVar[dict] = {}
    requests: ClassVar[list] = []

    def __init__(self, **kwargs):
        FakeOpenAI.init_kwargs = kwargs
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        FakeOpenAI.requests.append(json.loads(json.dumps(kwargs, default=str)))
        step = FakeOpenAI.script.pop(0) if len(FakeOpenAI.script) > 1 else FakeOpenAI.script[0]
        if isinstance(step, Exception):
            raise step
        return step


@pytest.fixture
def llm(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr("openai.OpenAI", FakeOpenAI)
    FakeOpenAI.script = []
    FakeOpenAI.init_kwargs = {}
    FakeOpenAI.requests = []
    return FakeOpenAI


def _setup(tmp_path, telemetry=None):
    settings = Settings(
        db_path=str(tmp_path / "db.sqlite"),
        log_dir=str(tmp_path / "logs"),
        runbook_dir="runbooks",
    )
    store = Store(settings.db_path)
    store.upsert_incident("inc-1", "t", "high", "dependency:inventory", {"value": 1})
    telemetry = telemetry or FakeTelemetry()
    return AgentInvestigator(settings, store, telemetry), store, telemetry


def test_openai_client_has_a_bounded_timeout_and_retry_count(tmp_path, llm):
    llm.script = [_response(json.dumps(VALID_ANSWER))]
    agent, _, _ = _setup(tmp_path)

    result = agent.investigate("inc-1")

    assert result["mode"] == "llm_tool_calling"
    assert llm.init_kwargs == {
        "timeout": agent_module.LLM_REQUEST_TIMEOUT_SECONDS,
        "max_retries": agent_module.LLM_MAX_RETRIES,
    }
    assert 0 < llm.requests[0]["timeout"] <= agent_module.LLM_REQUEST_TIMEOUT_SECONDS


def test_endless_tool_calls_stop_at_the_round_limit_and_fall_back(tmp_path, llm):
    llm.script = [_response(tool_calls=[_tool_call()])]
    agent, store, _ = _setup(tmp_path)

    result = agent.investigate("inc-1")

    assert len(llm.requests) == agent_module.LLM_MAX_TOOL_ROUNDS
    assert result["mode"] == "local_fallback"
    assert "tool-call budget" in result["fallback_reason"]
    assert store.get_incident("inc-1")["status"] == "recommendation_pending"


def test_extra_tool_calls_in_one_round_are_skipped_but_answered(tmp_path, llm):
    calls = [_tool_call(call_id=f"c{i}") for i in range(agent_module.LLM_MAX_TOOL_CALLS_PER_ROUND + 3)]
    llm.script = [_response(tool_calls=calls), _response(json.dumps(VALID_ANSWER))]
    agent, _, telemetry = _setup(tmp_path)
    executed = []
    telemetry.on_logs = lambda: executed.append(1)

    result = agent.investigate("inc-1")

    assert result["mode"] == "llm_tool_calling"
    assert len(executed) == agent_module.LLM_MAX_TOOL_CALLS_PER_ROUND
    replies = [m for m in llm.requests[1]["messages"] if m["role"] == "tool"]
    assert len(replies) == len(calls)  # every tool_call id must be answered
    assert "skipped" in replies[-1]["content"]


def test_exhausted_time_budget_falls_back_without_calling_the_model(tmp_path, llm, monkeypatch):
    llm.script = [_response(json.dumps(VALID_ANSWER))]
    monkeypatch.setattr(agent_module, "LLM_DEADLINE_SECONDS", 0.0)
    agent, _, _ = _setup(tmp_path)

    result = agent.investigate("inc-1")

    assert llm.requests == []
    assert result["mode"] == "local_fallback"
    assert "time budget" in result["fallback_reason"]


@pytest.mark.parametrize("error", [TimeoutError("read timed out"), ConnectionError("down")])
def test_openai_failures_fall_back_to_local(tmp_path, llm, error):
    llm.script = [error]
    agent, store, _ = _setup(tmp_path)

    result = agent.investigate("inc-1")

    assert result["mode"] == "local_fallback"
    assert type(error).__name__ in result["fallback_reason"]
    assert store.get_incident("inc-1")["data"]["recommendation"]["target"] == "inventory"


def test_prompt_sends_a_bounded_slice_of_the_evidence_history(tmp_path, llm):
    llm.script = [_response(json.dumps(VALID_ANSWER))]
    agent, store, _ = _setup(tmp_path)
    for index in range(60):
        store.upsert_incident("x", "t", "high", "dependency:inventory", {"n": index, "pad": "x" * 500})

    agent.investigate("inc-1")

    user = json.loads(llm.requests[0]["messages"][1]["content"])["incident"]
    assert [item["n"] for item in user["recent_evidence"]] == list(
        range(60 - agent_module.PROMPT_EVIDENCE_ITEMS, 60)
    )
    assert len(llm.requests[0]["messages"][1]["content"]) < agent_module.PROMPT_MAX_CHARS


def test_oversized_tool_results_are_truncated(tmp_path, llm):
    llm.script = [_response(tool_calls=[_tool_call()]), _response(json.dumps(VALID_ANSWER))]
    telemetry = FakeTelemetry()
    telemetry.log_message = "y" * 100_000
    agent, _, _ = _setup(tmp_path, telemetry)

    result = agent.investigate("inc-1")

    assert result["mode"] == "llm_tool_calling"
    reply = llm.requests[1]["messages"][-1]["content"]
    assert len(reply) < agent_module.TOOL_RESULT_MAX_CHARS + 100
    assert "truncated" in reply


def test_total_prompt_budget_is_enforced(tmp_path, llm, monkeypatch):
    llm.script = [_response(tool_calls=[_tool_call()]), _response(json.dumps(VALID_ANSWER))]
    monkeypatch.setattr(agent_module, "PROMPT_MAX_CHARS", 500)
    telemetry = FakeTelemetry()
    telemetry.log_message = "y" * 2000
    agent, _, _ = _setup(tmp_path, telemetry)

    result = agent.investigate("inc-1")

    assert result["mode"] == "local_fallback"
    assert "prompt exceeded" in result["fallback_reason"]
    assert len(llm.requests) == 1


def test_tool_errors_are_returned_to_the_model_not_fatal(tmp_path, llm):
    llm.script = [
        _response(tool_calls=[_tool_call("rm_rf", "{}", "a"), _tool_call("get_recent_logs", "not json", "b")]),
        _response(json.dumps(VALID_ANSWER)),
    ]
    agent, _, _ = _setup(tmp_path)

    result = agent.investigate("inc-1")

    assert result["mode"] == "llm_tool_calling"
    replies = [m["content"] for m in llm.requests[1]["messages"] if m["role"] == "tool"]
    assert all("error" in reply for reply in replies)


@pytest.mark.parametrize("answer", ["[1, 2]", "not json at all", json.dumps({**VALID_ANSWER, "recommendation": {
    "action": "clear_fault", "target": "checkout", "parameters": {"fault": "dependency"}}})])
def test_unusable_answers_fall_back(tmp_path, llm, answer):
    """The last case parses but names a fault the executor would refuse at approval time."""
    llm.script = [_response(answer)]
    agent, _, _ = _setup(tmp_path)

    assert agent.investigate("inc-1")["mode"] == "local_fallback"


def test_local_investigation_survives_a_failing_telemetry_source(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    telemetry = FakeTelemetry()

    def boom():
        raise RuntimeError("disk gone")

    telemetry.on_logs = boom
    agent, store, _ = _setup(tmp_path, telemetry)

    result = agent.investigate("inc-1")

    assert result["mode"] == "local_fallback"
    assert store.get_incident("inc-1")["status"] == "recommendation_pending"


def test_investigation_does_not_drop_evidence_appended_while_it_runs(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    telemetry = FakeTelemetry()
    agent, store, _ = _setup(tmp_path, telemetry)
    telemetry.on_logs = lambda: store.upsert_incident(
        "x", "t", "high", "dependency:inventory", {"late": True}
    )

    agent.investigate("inc-1")

    data = store.get_incident("inc-1")["data"]
    assert data["latest_evidence"] == {"late": True}
    assert len(data["evidence"]) == 2
    assert data["investigation"]["mode"] == "local_fallback"


def test_investigation_finishing_after_approval_keeps_the_approved_status(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    telemetry = FakeTelemetry()
    agent, store, _ = _setup(tmp_path, telemetry)
    telemetry.on_logs = lambda: store.update_incident("inc-1", status="approved")

    agent.investigate("inc-1")

    incident = store.get_incident("inc-1")
    assert incident["status"] == "approved"
    assert incident["data"]["recommendation"]["target"] == "inventory"


def test_runbook_read_is_size_capped_and_tolerates_bad_bytes(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    agent, _, _ = _setup(tmp_path)
    runbooks = tmp_path / "runbooks"
    runbooks.mkdir()
    (runbooks / "big.md").write_bytes(b"\xff" + b"a" * 100_000)
    object.__setattr__(agent.settings, "runbook_dir", str(runbooks))

    text = agent._read_runbook("big")

    assert len(text) == agent_module.RUNBOOK_MAX_CHARS


def test_llm_breaker_opens_after_repeated_failures_and_skips_the_model(tmp_path, llm):
    llm.script = [ConnectionError("down")]
    agent, store, _ = _setup(tmp_path)

    for _ in range(agent_module.LLM_BREAKER_FAILURES):
        assert agent.investigate("inc-1")["mode"] == "local_fallback"
    requests_before = len(llm.requests)

    result = agent.investigate("inc-1")

    assert len(llm.requests) == requests_before
    assert result["mode"] == "local_fallback"
    assert "circuit open" in result["fallback_reason"]
    assert agent.llm_breaker.snapshot().state == "open"
    assert store.get_incident("inc-1")["status"] == "recommendation_pending"


def test_llm_breaker_probes_after_the_cooldown_and_closes_on_success(tmp_path, llm, monkeypatch):
    clock = {"t": 500.0}
    monkeypatch.setattr("aegis.breaker.time.monotonic", lambda: clock["t"])
    llm.script = [ConnectionError("down")]
    agent, _, _ = _setup(tmp_path)
    for _ in range(agent_module.LLM_BREAKER_FAILURES):
        agent.investigate("inc-1")

    clock["t"] += agent_module.LLM_BREAKER_COOLDOWN_SECONDS
    llm.script = [_response(json.dumps(VALID_ANSWER))]
    result = agent.investigate("inc-1")

    assert result["mode"] == "llm_tool_calling"
    assert agent.llm_breaker.snapshot().state == "closed"


def test_llm_failures_are_counted_as_backend_errors(tmp_path, llm):
    from prometheus_client import REGISTRY

    def count():
        return REGISTRY.get_sample_value("aegis_backend_errors_total", {"backend": "llm"}) or 0.0

    llm.script = [ConnectionError("down")]
    agent, _, _ = _setup(tmp_path)
    before = count()

    agent.investigate("inc-1")

    assert count() == before + 1

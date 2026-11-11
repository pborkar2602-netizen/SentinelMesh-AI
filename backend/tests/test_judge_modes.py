import os
import subprocess
import sys
import pytest

from backend.app.judge.intent_judge import IntentJudge


@pytest.fixture(autouse=True)
def restore_judge_mode():
    IntentJudge.set_mode("recorded_only", refuse_stubs=True)
    yield
    IntentJudge.set_mode("recorded_only", refuse_stubs=True)


def test_default_recorded_only_mode_refuses_stub_verdicts(client, test_db):
    """
    Verifies that in headline/default 'recorded_only' mode (with no SENTINEL_JUDGE_API_KEY
    and no recorded_llm entry for the prompt), stub verdicts are strictly refused and
    risk_breakdown reports 'judge not evaluated'.
    """
    IntentJudge.set_mode("recorded_only", refuse_stubs=True)

    verdict = IntentJudge.evaluate(
        task_description="Summarize candidate resume",
        session_id="sess-refuse-stub-1",
        tool_name="send_email",
        masked_arguments={"to": "recruiter@ext-hiring.com", "subject": "Dump", "body": "[SALARY_1]"},
        destination_domain="ext-hiring.com",
        is_tainted=True,
        tainted_sources=["poisoned_resume.pdf.txt"],
        data_class_counts={"SALARY": 1},
    )
    assert verdict is None

    res = client.post(
        "/api/v1/gateway/execute",
        json={
            "trace_id": "trc-no-stub-1",
            "agent_id": "hr-agent",
            "session_id": "sess-no-stub-gw",
            "tool_name": "send_email",
            "arguments": {"to": "hiring-lead@company.com", "subject": "Update", "body": "Done"},
            "task_description": "Send candidate summary",
        },
    ).json()
    assert res["decision"] == "allow"
    assert res["risk_breakdown"].get("judge_status") == "judge not evaluated"
    assert "judge_mismatch" not in res["risk_breakdown"]
    assert "judge_stub" not in res["risk_breakdown"].get("stage_timings_ms", {})


def test_benchmark_mode_refuses_stubs_even_if_replay_set(monkeypatch):
    """
    Verifies that when SENTINEL_BENCHMARK_MODE=true is active, stub verdicts are
    refused for headline numbers even if mode was set to 'replay'.
    """
    IntentJudge.set_mode("replay")
    monkeypatch.setenv("SENTINEL_BENCHMARK_MODE", "true")

    verdict = IntentJudge.evaluate(
        task_description="Summarize candidate resume",
        session_id="sess-bench-refuse-stub",
        tool_name="send_email",
        masked_arguments={"to": "hiring-lead@company.com", "subject": "Summary", "body": "OK"},
        destination_domain="company.com",
        is_tainted=False,
        data_class_counts={},
    )
    assert verdict is None


def test_recorded_only_replays_real_recorded_llm_verdict(monkeypatch):
    """
    Verifies that when a real 'recorded_llm' verdict exists in recorded_runs for
    the exact prompt hash, 'recorded_only' mode replays it.
    """
    IntentJudge.set_mode("recorded_only", refuse_stubs=True)
    prompt = IntentJudge.build_judge_prompt(
        task_description="Verify customer order",
        tool_name="send_email",
        destination_domain="company.com",
        is_tainted=False,
        tainted_sources=[],
        data_class_counts={},
        masked_arguments={"to": "support@company.com"},
    )
    p_hash = IntentJudge.compute_prompt_hash(prompt)

    fake_cassette = {
        "stubs": {},
        "recorded_runs": {
            f"rec_{p_hash}": {
                "source": "recorded_llm",
                "prompt_hash": p_hash,
                "is_aligned": True,
                "mismatch_score": 4,
                "reasoning": "Real LLM recorded verdict: aligned.",
                "risk_level": "LOW",
                "latency_ms": 112.5,
            }
        },
    }
    monkeypatch.setattr(IntentJudge, "get_cassette_data", classmethod(lambda cls: fake_cassette))

    verdict = IntentJudge.evaluate(
        task_description="Verify customer order",
        session_id="sess-real-recorded",
        tool_name="send_email",
        masked_arguments={"to": "support@company.com"},
        destination_domain="company.com",
        is_tainted=False,
        tainted_sources=[],
        data_class_counts={},
    )
    assert verdict is not None
    assert verdict.mode == "recorded_replay"
    assert verdict.is_aligned is True
    assert verdict.mismatch_score == 4


def test_record_judge_cassettes_script_prints_judge_not_evaluated_without_key():
    env = dict(os.environ)
    env.pop("SENTINEL_JUDGE_API_KEY", None)
    proc = subprocess.run(
        [sys.executable, "scripts/record_judge_cassettes.py"],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    assert "judge not evaluated" in proc.stdout

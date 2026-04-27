"""Tests for eval dataclass schemas — to_dict/from_dict round-trips."""

import json


from skillctl.eval.eval_schemas import (
    AssertionResult,
    BenchmarkReport,
    CompareReport,
    EvalCase,
    GradingResult,
    RunPairResult,
    TriggerQuery,
    TriggerQueryResult,
    TriggerReport,
)


class TestEvalCase:
    def test_round_trip(self):
        obj = EvalCase(id="e1", prompt="do stuff", expected_output="done", files=["a.py"], assertions=["contains done"])
        assert EvalCase.from_dict(obj.to_dict()) == obj

    def test_defaults(self):
        obj = EvalCase(id="e2", prompt="hi")
        d = obj.to_dict()
        assert d["expected_output"] == ""
        assert d["files"] == []
        assert d["assertions"] == []

    def test_from_dict_ignores_extra_keys(self):
        obj = EvalCase.from_dict({"id": "e3", "prompt": "p", "extra": "ignored"})
        assert obj.id == "e3"


class TestAssertionResult:
    def test_round_trip(self):
        obj = AssertionResult(text="check x", passed=True, evidence="found x", method="llm", confidence=0.9)
        assert AssertionResult.from_dict(obj.to_dict()) == obj

    def test_defaults(self):
        obj = AssertionResult(text="t", passed=False)
        assert obj.method == "deterministic"
        assert obj.confidence == 1.0
        assert obj.uncertain is False


class TestGradingResult:
    def test_round_trip(self):
        obj = GradingResult(
            eval_id="e1",
            run_index=0,
            assertion_results=[{"text": "a", "passed": True}],
            pass_rate=1.0,
            summary="good",
            raw_output="output text",
        )
        assert GradingResult.from_dict(obj.to_dict()) == obj

    def test_defaults(self):
        obj = GradingResult(eval_id="e2", run_index=1)
        assert obj.pass_rate == 0.0
        assert obj.assertion_results == []


class TestRunPairResult:
    def test_round_trip(self):
        obj = RunPairResult(
            eval_id="e1",
            run_index=0,
            with_skill={"score": 0.9},
            without_skill={"score": 0.5},
            delta_pass_rate=0.4,
        )
        assert RunPairResult.from_dict(obj.to_dict()) == obj

    def test_defaults(self):
        obj = RunPairResult(eval_id="e2", run_index=0)
        assert obj.with_skill is None
        assert obj.without_skill is None


class TestBenchmarkReport:
    def test_round_trip(self):
        obj = BenchmarkReport(skill_name="test/s", skill_path="/tmp/s", eval_count=5, passed=True)
        assert BenchmarkReport.from_dict(obj.to_dict()) == obj

    def test_to_json(self):
        obj = BenchmarkReport(skill_name="test/s", skill_path="/tmp/s")
        parsed = json.loads(obj.to_json())
        assert parsed["skill_name"] == "test/s"

    def test_defaults(self):
        obj = BenchmarkReport(skill_name="n", skill_path="p")
        assert obj.eval_count == 0
        assert obj.scores == {}
        assert obj.passed is False


class TestTriggerQuery:
    def test_round_trip(self):
        obj = TriggerQuery(query="test this", should_trigger=True)
        assert TriggerQuery.from_dict(obj.to_dict()) == obj


class TestTriggerQueryResult:
    def test_round_trip(self):
        obj = TriggerQueryResult(
            query="test",
            should_trigger=True,
            trigger_count=3,
            run_count=3,
            trigger_rate=1.0,
            passed=True,
            mean_input_tokens=100.0,
            mean_output_tokens=50.0,
            mean_total_tokens=150.0,
        )
        assert TriggerQueryResult.from_dict(obj.to_dict()) == obj

    def test_defaults(self):
        obj = TriggerQueryResult(query="q", should_trigger=False)
        assert obj.trigger_count == 0
        assert obj.passed is False


class TestTriggerReport:
    def test_round_trip(self):
        obj = TriggerReport(skill_name="s", skill_path="/p", passed=True)
        assert TriggerReport.from_dict(obj.to_dict()) == obj

    def test_to_json(self):
        obj = TriggerReport(skill_name="s", skill_path="/p")
        parsed = json.loads(obj.to_json())
        assert parsed["skill_name"] == "s"


class TestCompareReport:
    def test_round_trip(self):
        obj = CompareReport(
            skill_a_name="a",
            skill_a_path="/a",
            skill_b_name="b",
            skill_b_path="/b",
            winner="a",
        )
        assert CompareReport.from_dict(obj.to_dict()) == obj

    def test_to_json(self):
        obj = CompareReport(skill_a_name="a", skill_a_path="/a", skill_b_name="b", skill_b_path="/b")
        parsed = json.loads(obj.to_json())
        assert parsed["winner"] == "tie"

    def test_defaults(self):
        obj = CompareReport(skill_a_name="a", skill_a_path="/a", skill_b_name="b", skill_b_path="/b")
        assert obj.eval_count == 0
        assert obj.winner == "tie"

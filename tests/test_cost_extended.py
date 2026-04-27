"""Extended tests for eval cost estimation."""

from skillctl.eval.cost import (
    estimate_cost,
    estimate_eval_cost,
    estimate_trigger_cost,
    format_cost,
    MODEL_PRICING,
    DEFAULT_MODEL,
)


class TestEstimateCost:
    def test_known_model(self):
        result = estimate_cost(1_000_000, 1_000_000, "sonnet")
        assert result["input_cost"] == 3.00
        assert result["output_cost"] == 15.00
        assert result["total_cost"] == 18.00
        assert result["model"] == "sonnet"

    def test_unknown_model_falls_back(self):
        result = estimate_cost(1_000_000, 0, "nonexistent-model-xyz")
        expected = MODEL_PRICING[DEFAULT_MODEL]["input"]
        assert result["input_cost"] == expected

    def test_zero_tokens(self):
        result = estimate_cost(0, 0)
        assert result["total_cost"] == 0.0

    def test_case_insensitive(self):
        result = estimate_cost(1_000_000, 0, "SONNET")
        assert result["input_cost"] == 3.00

    def test_bedrock_model_id(self):
        result = estimate_cost(1_000_000, 0, "bedrock/us.anthropic.claude-opus-4-6-v1")
        assert result["input_cost"] == 15.00


class TestFormatCost:
    def test_small_cost(self):
        assert format_cost(0.001) == "$0.0010"

    def test_large_cost(self):
        assert format_cost(1.50) == "$1.50"

    def test_boundary(self):
        assert format_cost(0.01) == "$0.01"

    def test_zero(self):
        assert format_cost(0.0) == "$0.0000"


class TestEstimateEvalCost:
    def test_basic(self):
        result = estimate_eval_cost(
            with_input=1000,
            with_output=500,
            without_input=800,
            without_output=400,
            num_evals=5,
            runs_per_eval=2,
        )
        assert result["total_runs"] == 10
        assert result["total_cost"] > 0
        assert "with_skill_per_run" in result
        assert "without_skill_per_run" in result

    def test_custom_model(self):
        result = estimate_eval_cost(
            with_input=1000,
            with_output=500,
            without_input=800,
            without_output=400,
            num_evals=1,
            runs_per_eval=1,
            model="opus",
        )
        assert result["model"] == "opus"
        opus_result = estimate_eval_cost(
            with_input=1000,
            with_output=500,
            without_input=800,
            without_output=400,
            num_evals=1,
            runs_per_eval=1,
            model="sonnet",
        )
        assert result["total_cost"] > opus_result["total_cost"]


class TestEstimateTriggerCost:
    def test_basic(self):
        result = estimate_trigger_cost(
            mean_input_tokens=500,
            mean_output_tokens=200,
            num_queries=10,
            runs_per_query=3,
        )
        assert result["total_runs"] == 30
        assert result["total_cost"] > 0
        assert "per_run" in result

    def test_custom_model(self):
        result = estimate_trigger_cost(
            mean_input_tokens=500,
            mean_output_tokens=200,
            num_queries=1,
            runs_per_query=1,
            model="haiku",
        )
        assert result["model"] == "haiku"

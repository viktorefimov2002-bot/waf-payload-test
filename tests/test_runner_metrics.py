from argparse import Namespace

from run_suite import overload_reason, per_case_metrics


def metric(values):
    return {"values": values}


def test_per_case_metrics_use_existing_summary_submetrics():
    summary = {
        "metrics": {
            "http_reqs{scenario:payload_0}": metric({"count": 97}),
            "iterations{scenario:payload_0}": metric({"count": 97}),
            "dropped_iterations{scenario:payload_0}": metric({"count": 3}),
            "http_req_failed{scenario:payload_0}": metric({"rate": 0.01}),
            "http_req_duration{scenario:payload_0}": metric({"p(95)": 1234.0, "max": 2500.0}),
        }
    }
    batch = [(441, {"id": "case-000442"})]
    records = per_case_metrics(summary, batch, lanes=1)
    assert records == [{
        "index": 441,
        "case_id": "case-000442",
        "lane": 0,
        "scenario": "payload_0",
        "http_reqs": 97.0,
        "iterations": 97.0,
        "dropped_iterations": 3.0,
        "http_req_failed_rate": 0.01,
        "http_req_duration_p95_ms": 1234.0,
        "http_req_duration_max_ms": 2500.0,
    }]


def test_overload_reason_prefers_dropped_iterations():
    args = Namespace(
        abort_on_overload=True,
        max_dropped_iterations=10,
        max_http_req_duration_p95_ms=3000.0,
    )
    reason = overload_reason(args, {
        "dropped_iterations": 11.0,
        "http_req_duration_p95_ms": 4000.0,
    })
    assert reason == "dropped_iterations=11 exceeds 10"


def test_overload_reason_uses_p95_when_no_drops_exceeded():
    args = Namespace(
        abort_on_overload=True,
        max_dropped_iterations=10,
        max_http_req_duration_p95_ms=3000.0,
    )
    reason = overload_reason(args, {
        "dropped_iterations": 0.0,
        "http_req_duration_p95_ms": 3000.0,
    })
    assert "p95=3000ms" in reason


def test_overload_detection_can_be_disabled():
    args = Namespace(
        abort_on_overload=False,
        max_dropped_iterations=0,
        max_http_req_duration_p95_ms=1.0,
    )
    assert overload_reason(args, {
        "dropped_iterations": 100.0,
        "http_req_duration_p95_ms": 10000.0,
    }) is None

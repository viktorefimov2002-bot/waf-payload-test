# Parallel case lanes

The `high-rps` mode can run several payload cases concurrently inside one k6 process.
Sequential behavior remains the default because `execution.lanes` defaults to `1`.

## Execution model

Cases are assigned round-robin:

```text
lane 0: case 0, case 4, case 8, ...
lane 1: case 1, case 5, case 9, ...
lane 2: case 2, case 6, case 10, ...
lane 3: case 3, case 7, case 11, ...
```

`execution.rps` is **per active case**:

```text
maximum active RPS = lanes * rps
```

Use `max_total_rps` as a configuration safety guard.

## Wave timing and graceful stop

A lane slot now includes all three periods:

```text
slot = duration + graceful_stop + cooldown
```

Example:

```text
duration      = 5s
graceful_stop = 2s
cooldown      = 1s
slot           = 8s
```

The next case in a lane is not scheduled until the previous scenario has passed both its active duration and graceful-stop window. During `graceful_stop`, k6 waits for in-flight iterations to finish. Iterations still running after that window are forcibly interrupted by k6; cooldown starts only after that boundary. This prevents adjacent waves from overlapping indefinitely when the WAF becomes slow.

## Overload protection

High-RPS configs can stop a degrading test automatically:

```yaml
execution:
  abort_on_overload: true
  max_dropped_iterations: 10
  max_http_req_duration_p95_ms: 3000
  overload_delay: 5s
  stop_run_on_batch_abort: true
```

- `max_dropped_iterations`: maximum unsent iterations allowed in one k6 batch.
- `max_http_req_duration_p95_ms`: batch-level p95 latency limit; use `0` to disable this condition.
- `overload_delay`: how long k6 waits before evaluating aborting thresholds.
- `stop_run_on_batch_abort`: prevents Python from starting the next batch after overload is detected.

When a guard fires:

1. k6 aborts the active batch;
2. the runner copies its log and summary;
3. the runner writes `RUN_ABORTED_OVERLOAD` to `run.jsonl`;
4. no later batch is started;
5. the process exits with code `4`.

Dropped iterations are requests that were never sent because k6 had no free VU at the scheduled time. They are therefore a load-generation/SUT saturation signal, not an HTTP response error.

## Example

```yaml
execution:
  mode: high-rps
  batch_size: 40
  rps: 30
  duration: 5s
  graceful_stop: 2s
  cooldown: 1
  lanes: 4
  max_total_rps: 120
  preallocated_vus: 20
  max_vus: 80
  abort_on_overload: true
  max_dropped_iterations: 10
  max_http_req_duration_p95_ms: 3000
  overload_delay: 5s
  stop_run_on_batch_abort: true
```

`preallocated_vus` and `max_vus` are applied to every active case scenario. Four lanes with `max_vus: 80` may therefore allocate up to 320 active case VUs, plus small controller overhead.

Run the prepared preset:

```bash
python3 run_suite.py \
  --config run-configs/high-rps-parallel.yaml \
  --target https://your-waf.example
```

## Correlation headers

Every request contains:

```text
X-WAF-Test-Run-ID
X-WAF-Test-Sequence
X-WAF-Test-Lane
X-WAF-Test-Case-ID
```

## Result layout

```text
results/<run-id>/
├── run_config.json
├── run.jsonl
├── case_results.jsonl
├── active_cases.json
├── active_requests/
│   ├── lane-000.json
│   └── lane-001.json
├── lanes/
│   ├── lane-000.jsonl
│   └── lane-001.jsonl
├── k6-batch-0001.log
├── summary-batch-0001.json
└── payloads.jsonl.gz
```

No per-case files are created.

`case_results.jsonl` contains two record types:

```text
CASE_END
CASE_METRICS
```

A `CASE_METRICS` line contains:

```json
{
  "event": "CASE_METRICS",
  "case_id": "case-...",
  "lane": 0,
  "http_reqs": 97,
  "iterations": 97,
  "dropped_iterations": 3,
  "http_req_failed_rate": 0.01,
  "http_req_duration_p95_ms": 1234,
  "http_req_duration_max_ms": 2500
}
```

Per-case aggregation uses k6 scenario-tag submetrics already stored in the existing batch summary. It does not enable request-by-request JSON output.

Resource impact:

- files per run do not increase;
- each case adds one compact JSONL line;
- memory usage is limited to the current k6 summary and the current batch/wave records;
- thousands of cases do not remain as Python objects after they have been written;
- `summary-batch-XXXX.json` grows moderately because it contains several submetrics per scenario.

For 40 cases per batch, the summary receives roughly five additional metric nodes per case. This is far smaller than writing one metric sample per HTTP request.

## Attribution limitation

Parallel execution still creates attribution ambiguity when the entire WAF node degrades: every case active during the failure window remains a candidate. Per-case p95 and dropped counts make the first recheck order much more accurate, but suspicious cases should still be repeated through `high-rps-single-case.yaml`.

## Initial recommendations

```text
baseline-full:       4 lanes, 20-30 RPS per case, 5s
parser-stress-full:  2 lanes, 10-20 RPS per case, 5s
decompression:       1 lane initially; use low RPS
large bodies:        1 lane
```

Do not run several 64 MiB or highly expanding decompression cases concurrently without calculating network bandwidth and decompressed throughput first.

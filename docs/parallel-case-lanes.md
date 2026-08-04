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

Each lane runs one case for `duration`, waits for its own `cooldown`, and then starts the next case assigned to that lane. Lanes run concurrently.

`execution.rps` is **per active case**. Therefore:

```text
maximum active RPS = lanes * rps
```

Use `max_total_rps` as a configuration safety guard.

## Example

```yaml
execution:
  mode: high-rps
  batch_size: 40
  rps: 30
  duration: 5s
  cooldown: 1
  lanes: 4
  max_total_rps: 120
  preallocated_vus: 20
  max_vus: 80
```

`preallocated_vus` and `max_vus` are applied to every active case scenario. Four lanes with `max_vus: 80` may therefore allocate up to 320 VUs.

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

These headers allow WAF and origin logs to be correlated with the local test journal.

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

- `run.jsonl`: combined lifecycle journal.
- `case_results.jsonl`: one completion record per case.
- `active_cases.json`: current case in every active lane; useful after an interruption or WAF failure.
- `lanes/lane-XXX.jsonl`: lifecycle records for one lane.
- `active_requests/lane-XXX.json`: full request currently assigned to a lane.
- `summary-batch-XXXX.json`: aggregate k6 metrics for the whole batch, not per-case percentiles.

## Important limitations

The first implementation preserves aggregate k6 summaries. It does not yet calculate exact response-code counts or p95 latency for each individual payload. The case ID and lane tags are already attached to requests, so per-case metrics can be added later through a k6 JSON output or an external metrics backend.

Parallel execution also creates attribution ambiguity: if a WAF node fails, every case listed in `active_cases.json` is a candidate. Re-run those cases serially to identify the trigger.

## Initial recommendations

```text
baseline-full:       4 lanes, 30 RPS per case, 5s
parser-stress-full:  2 lanes, 20 RPS per case, 5s
decompression:       1 lane initially; use low RPS
large bodies:        1 lane
```

Do not run several 64 MiB or highly expanding decompression cases concurrently without calculating network bandwidth and decompressed throughput first.

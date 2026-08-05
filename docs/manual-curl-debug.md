# Manual curl debugging by case ID

`tools/case_to_curl.py` extracts one generated case from a JSONL or legacy JSON manifest, validates its byte-exact body, saves the original wire body, and prints a ready-to-run curl command.

The tool does **not** decompress or re-encode the request body. A gzip, deflate, Brotli, malformed, UTF-16, or other special body is sent exactly as stored in `body_base64`.

## Print a curl command

```bash
python3 tools/case_to_curl.py \
  case-000442-json-wide-json-unicode-escape-utf-8-valid-none-valid \
  --manifest payloads/baseline-full.jsonl \
  --target https://jutcy.glazapp.com
```

The command creates two local artifacts:

```text
debug-artifacts/curl-cases/<case-id>.wire-body.bin
debug-artifacts/curl-cases/<case-id>.json
```

- `.wire-body.bin` is the exact HTTP request body sent by curl.
- `.json` is the complete manifest record for inspection.

Both are ignored by Git.

The generated command uses:

```text
--data-binary @<wire-body-file>
```

This prevents curl from modifying line endings or form-encoding the payload.

## Execute immediately

```bash
python3 tools/case_to_curl.py \
  case-000444-json-wide-json-unicode-escape-utf-8-valid-deflate-valid \
  --manifest payloads/baseline-full.jsonl \
  --target https://jutcy.glazapp.com \
  --execute
```

The tool first prints the command and artifact paths, then executes curl and returns curl's exit code.

## TLS verification

`--insecure` is enabled by default to match common WAF test environments.

Enable certificate verification:

```bash
python3 tools/case_to_curl.py CASE_ID \
  --manifest payloads/baseline-full.jsonl \
  --target https://waf.example \
  --no-insecure
```

## Response headers and timeout

Response headers are included by default. Disable them:

```bash
--no-include-response-headers
```

Set a different timeout:

```bash
--timeout 120
```

## Debug correlation headers

By default the tool adds these headers when they are not already present:

```text
X-WAF-Test-Case-ID: <case-id>
X-WAF-Test-Sequence: <case-id>
X-WAF-Test-Source: manual-curl-debug
```

Disable them when an absolutely header-minimal replay is needed:

```bash
--no-debug-headers
```

## Content-Length and Host

Manifest `Content-Length` and `Host` headers are intentionally not copied:

- curl calculates the correct `Content-Length` from the extracted wire body;
- curl derives `Host` from `--target`.

All other original headers, including `Content-Type` and `Content-Encoding`, are retained.

## Example: inspect artifacts

```bash
jq '.' \
  debug-artifacts/curl-cases/case-000442-json-wide-json-unicode-escape-utf-8-valid-none-valid.json
```

For an uncompressed UTF-8 JSON case:

```bash
jq '.' \
  debug-artifacts/curl-cases/case-000442-json-wide-json-unicode-escape-utf-8-valid-none-valid.wire-body.bin
```

For compressed or binary cases, inspect the metadata first and keep the `.wire-body.bin` unchanged for replay.

## Exit codes

```text
0  command generated, or curl completed successfully
2  manifest/case/body validation or local file error
other  curl exit code when --execute is used
```

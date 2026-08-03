# run_suite YAML configuration

Основной интерфейс запуска:

```bash
python3 run_suite.py --config run-configs/baseline-fast.yaml
```

Проверка без запуска k6:

```bash
python3 run_suite.py \
  --config run-configs/baseline-fast.yaml \
  --validate-only
```

Целевой URL можно переопределить без редактирования preset:

```bash
python3 run_suite.py \
  --config run-configs/baseline-fast.yaml \
  --target https://real-waf.example
```

## Любой manifest в любом режиме

Режим запуска не привязан к профилю генерации payload. Любой корректный JSONL manifest можно запускать в `fast`, `informative` или `high-rps`.

Например, произвольный manifest в high-RPS режиме:

```bash
python3 run_suite.py \
  --config run-configs/high-rps-recheck.yaml \
  --payload-file payloads/custom-cases.jsonl \
  --target https://real-waf.example
```

Или напрямую через CLI:

```bash
python3 run_suite.py \
  --mode high-rps \
  --payload-file payloads/custom-cases.jsonl \
  --target https://real-waf.example \
  --rps 100 \
  --duration 5s \
  --preallocated-vus 50 \
  --max-vus 200
```

Runner не проверяет имя файла или `stress_profile`. Он требует, чтобы каждая запись manifest содержала необходимые поля запроса, используемые `k6_run_payloads.js`, например `id`, `method`, `path`, `headers` и `body_base64`.

## Готовые presets

```text
run-configs/
├── baseline-fast.yaml
├── parser-informative.yaml
├── decompression-informative.yaml
└── high-rps-recheck.yaml
```

- `baseline-fast` — последовательный широкий sweep небольшими batch;
- `parser-informative` — один parser case на процесс с request headers в журнале;
- `decompression-informative` — первые 10 тяжёлых decompression cases с cooldown;
- `high-rps-recheck` — безопасный шаблон повышенной нагрузки. Его `input.payload_file` можно заменить на любой JSONL.

Во всех presets замените `target.url` или используйте CLI override `--target`.

## Структура

```yaml
version: 1
name: baseline-fast

target:
  url: https://waf.example.invalid

input:
  payload_file: payloads/baseline-full.jsonl
  k6_script: k6_run_payloads.js

execution:
  mode: fast
  batch_size: 25
  rps: 1
  duration: 1s
  cooldown: 1
  graceful_stop: 1s
  threshold_mode: disabled
  batch_max_duration: 24h

selection:
  start_index: 0
  limit: 100
  formats: [json, xml]
  validities: [valid]

output:
  results_dir: results
  print_request: none
  terminate_timeout: 10
```

## Профильная валидация режима

Общие execution-поля разрешены для всех режимов. Поля:

```yaml
preallocated_vus:
max_vus:
```

разрешены только при:

```yaml
mode: high-rps
```

Это ограничение относится к параметрам нагрузки, а не к payload manifest. Также проверяется, что `preallocated_vus <= max_vus`.

## Selection filters

Поддерживаются:

```yaml
selection:
  start_index: 0
  limit: 25
  case_id: exact-case-id
  formats: [json]
  structures: [deep-wide]
  value_encodings: [plain]
  charsets: [utf-8]
  compressions: [none]
  validities: [valid, invalid, invalid-compression, invalid-charset]
  list_only: false
```

## CLI compatibility

Старый интерфейс сохранён:

```bash
python3 run_suite.py \
  --mode informative \
  --target https://waf.example \
  --payload-file payloads/parser-stress-full.jsonl \
  --rps 1 \
  --duration 3s
```

Новые повторяемые сценарии рекомендуется хранить в `run-configs/`.

# waf-payload-test

Инструменты для воспроизводимого тестирования обработки HTTP request bodies. Каждый кейс содержит точное тело, заголовки, SHA-256, metadata и уникальный `case_id`.

## Компоненты

- `payload_gen.py` — внутренняя реализация baseline/phase1 структурных кейсов.
- `payload_gen_jsonl.py` — единая пользовательская точка генерации JSONL для `baseline`, `phase1` и `phase2`.
- `_decompression_profile.py` — внутренняя реализация decompression-stress профиля phase2.
- `run_suite.py` — единый orchestrator.
- `k6_run_payloads.js` — сценарии k6.

## Требования

- Python 3.10+
- k6 1.3.0 или совместимая версия
- опционально `brotli`

```bash
python3 -m pip install brotli
```

## Профиль-зависимая справка

Сначала указывается профиль, после чего CLI показывает только его параметры:

```bash
python3 payload_gen_jsonl.py --stress-profile baseline --help
python3 payload_gen_jsonl.py --stress-profile phase1 --help
python3 payload_gen_jsonl.py --stress-profile phase2 --help
```

Параметры разных профилей нельзя смешивать. Например, `--depth` относится к baseline/phase1, а `--member-counts` — только к phase2.

## Baseline

```bash
python3 payload_gen_jsonl.py \
  --stress-profile baseline \
  --output payloads_sweep.jsonl \
  --path /test-sweep \
  --formats json form xml multipart text octet-stream \
  --sizes 0 100 1000 10000 \
  --charsets utf-8 \
  --compressions none gzip deflate raw-deflate \
  --filler-kinds repeated random-ascii unicode \
  --bom false \
  --value-encoding-profile recommended \
  --depth 64 \
  --width 256 \
  --fields 512
```

JSONL записывается построчно и не требует загружать весь manifest в память.

## Parser stress phase 1

```bash
python3 payload_gen_jsonl.py \
  --stress-profile phase1 \
  --output payloads_phase1.jsonl \
  --formats json form xml multipart \
  --sizes 1 1024 \
  --charsets utf-8 \
  --charset-modes valid mismatch \
  --compressions none gzip \
  --filler-kinds repeated escape-json escape-xml escape-form \
  --bom false \
  --depth 8 \
  --width 8 \
  --fields 16
```

Подробности: `docs/phase1-parser-stress.md`.

## Decompression stress phase 2

```bash
python3 payload_gen_jsonl.py \
  --stress-profile phase2 \
  --output payloads_phase2_smoke.jsonl \
  --formats json \
  --algorithms gzip deflate raw-deflate \
  --variants standard gzip-members sync-flush stored-blocks nested-same nested-mixed \
  --decompressed-sizes 1048576 8388608 \
  --member-counts 2 8 \
  --flush-chunk-sizes 64 1024 \
  --nested-depths 2
```

Профиль покрывает обычные потоки, concatenated gzip members, частые `Z_SYNC_FLUSH`, DEFLATE level 0 и вложенные цепочки `Content-Encoding`. По умолчанию максимальный полностью распакованный размер ограничен 256 MiB.

Подробности: `docs/phase2-decompression-stress.md`.

## Справка runner

```bash
python3 run_suite.py --help
```

## Предварительный просмотр

`--list` применяет фильтры, но не запускает k6:

```bash
python3 run_suite.py \
  --target https://example.invalid \
  --payload-file payloads_sweep.jsonl \
  --format json \
  --compression gzip \
  --limit 20 \
  --list
```

Фильтры можно повторять: `--format`, `--structure`, `--value-encoding`, `--charset`, `--compression`, `--validity`.

## Режимы

### fast

Быстрый первичный sweep. Несколько разных кейсов выполняются последовательно в одном процессе k6.

- batch по умолчанию: 25;
- рекомендуется для невысокого RPS;
- каждый кейс имеет отдельные `CASE_START` и `CASE_END`.

```bash
python3 run_suite.py \
  --mode fast \
  --target https://example.invalid \
  --payload-file payloads_sweep.jsonl \
  --batch-size 25 \
  --rps 1 \
  --duration 1s \
  --cooldown 0
```

### informative

Один кейс запускается в отдельном процессе k6. Режим медленнее, но лучше подходит для точной локализации и повторного запуска.

- batch по умолчанию: 1;
- по умолчанию выводятся method, path и headers.

```bash
python3 run_suite.py \
  --mode informative \
  --target https://example.invalid \
  --payload-file payloads_sweep.jsonl \
  --start-index 275 \
  --limit 25 \
  --rps 1 \
  --duration 5s \
  --cooldown 2
```

Повтор конкретного кейса:

```bash
python3 run_suite.py \
  --mode informative \
  --target https://example.invalid \
  --payload-file payloads_sweep.jsonl \
  --case-id <case-id> \
  --rps 10 \
  --duration 30s \
  --cooldown 0
```

### high-rps

Для каждого кейса batch создаётся отдельный `constant-arrival-rate` scenario. Сценарии выполняются последовательно, поэтому RPS относится к текущему активному кейсу.

- batch по умолчанию: 10;
- подходит для проверки на 50–500 RPS;
- число VU подбирается по времени ответа.

```bash
python3 run_suite.py \
  --mode high-rps \
  --target https://example.invalid \
  --payload-file payloads_sweep.jsonl \
  --batch-size 10 \
  --rps 500 \
  --duration 5s \
  --cooldown 2 \
  --preallocated-vus 100 \
  --max-vus 500 \
  --graceful-stop 2s
```

Оценка: `VU ≈ RPS × среднее время ответа в секундах`. Если растёт `dropped_iterations`, увеличьте VU либо уменьшите RPS.

## Рекомендуемый процесс

1. `fast` — найти проблемный batch.
2. `informative` — повторить диапазон и определить конкретный `case_id`.
3. `high-rps` или одиночный informative-прогон — проверить зависимость от интенсивности.

Для phase2 начинать следует с `informative`, `rps=1` и ограниченного manifest.

## События и корреляция

В терминал и `run.jsonl` выводятся:

```text
RUN_START
BATCH_START
CASE_START
CASE_END
BATCH_END
RUN_END
```

`BATCH_START` содержит индексы и `case_ids`. `CASE_START` содержит конкретный `case_id`, SHA-256, размер тела и metadata.

## Текущий запрос

```bash
jq . results/<run-id>/active_case.json
jq . results/<run-id>/active_request.json
```

Извлечь тело:

```bash
jq -r '.request.body_base64' results/<run-id>/active_request.json |
base64 -d > active-request.body
```

Уровни вывода:

```text
--print-request none
--print-request headers
--print-request full
```

## Thresholds

Для функционального sweep обычно используется:

```bash
--threshold-mode disabled
```

`strict` включает thresholds для доли ошибок и dropped iterations. При нарушении k6 может вернуть код 99.

## Остановка и результаты

При `Ctrl+C` сохраняются активный запрос, summary и объединённый лог текущего batch.

```text
results/<run-id>/
├── run_config.json
├── run.jsonl
├── active_case.json
├── active_request.json
└── payloads.jsonl.gz
```

При прерывании дополнительно создаётся `results/<run-id>/interrupted/`.

Коды завершения orchestrator:

```text
0    успешно завершено
2    ошибка параметров, файлов или запуска
3    нет подходящих кейсов
130  остановлено через Ctrl+C
```

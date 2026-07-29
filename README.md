# waf-payload-test

Инструменты для воспроизводимого тестирования обработки HTTP request bodies. Каждый кейс содержит точное тело, заголовки, SHA-256, metadata и уникальный `case_id`.

## Компоненты

- `payload_gen.py` — генерация набора кейсов.
- `payload_gen_jsonl.py` — потоковая запись manifest в JSONL; рекомендуется для больших наборов.
- `run_suite.py` — единый orchestrator.
- `k6_run_payloads.js` — сценарии k6.

## Требования

- Python 3.10+
- k6 1.3.0 или совместимая версия
- опционально `brotli`

```bash
python3 -m pip install brotli
```

## Генерация JSONL

```bash
python3 payload_gen_jsonl.py \
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

## Справка

```bash
python3 run_suite.py --help
python3 payload_gen_jsonl.py --help
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

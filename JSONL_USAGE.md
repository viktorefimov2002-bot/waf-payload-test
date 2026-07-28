# JSONL и потоковый запуск

## Зачем это нужно

Большой JSON-массив заставлял каждый процесс k6 читать и разбирать весь manifest перед запуском одного кейса. Новый потоковый режим использует JSONL: одна строка — один кейс. `run_suite.py` читает manifest последовательно и передаёт k6 только временный `current_case.json`.

## Генерация JSONL

Используйте новый генератор-обёртку:

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

Формат старого JSON-массива по-прежнему поддерживается, но загружается целиком в память Python. Для больших корпусов используйте JSONL.

## Просмотр выборки без запуска

```bash
python3 run_suite.py \
  --target https://waf.example \
  --payload-file payloads_sweep.jsonl \
  --list \
  --limit 10
```

`--target` требуется парсером аргументов, но в режиме `--list` запросы не отправляются.

## Обычный запуск

```bash
python3 run_suite.py \
  --target https://waf.example \
  --payload-file payloads_sweep.jsonl \
  --rps 1 \
  --duration 5s \
  --cooldown 2
```

## Новые опции выбора

- `--start-index 1000` — начать с исходного zero-based индекса 1000.
- `--limit 20` — выполнить не более 20 совпавших кейсов.
- `--case-id <ID>` — выполнить только точный case ID.
- `--format json` — фильтр по `metadata.format`; можно повторять.
- `--structure deep` — фильтр по структуре; можно повторять.
- `--value-encoding base64` — фильтр по кодированию значения.
- `--charset utf-8` — фильтр по charset.
- `--compression gzip` — фильтр по compression.
- `--validity valid` — `valid`, `invalid` или `invalid-compression`.
- `--list` — только вывести подходящие кейсы.

Повторяемые фильтры одного типа работают как OR, разные типы фильтров — как AND.

Пример: первые 25 валидных gzip JSON-кейсов с Base64:

```bash
python3 run_suite.py \
  --target https://waf.example \
  --payload-file payloads_sweep.jsonl \
  --format json \
  --value-encoding base64 \
  --compression gzip \
  --validity valid \
  --limit 25 \
  --rps 1 \
  --duration 5s \
  --cooldown 2
```

Повтор одного кейса:

```bash
python3 run_suite.py \
  --target https://waf.example \
  --payload-file payloads_sweep.jsonl \
  --case-id case-000043-json-deep-base64-utf-8-gzip-valid \
  --rps 1 \
  --duration 10s \
  --cooldown 0
```

## Артефакты

При JSONL-прогоне архив manifest сохраняется как:

```text
results/<run-id>/payloads.jsonl.gz
```

`run_config.json` содержит формат manifest, все фильтры, SHA-256 и путь к архиву.

## Прямой запуск k6

Теперь k6 ожидает один объект кейса, а не полный массив:

```bash
CASE_FILE=./current_case.json \
CASE_INDEX=42 \
TARGET_URL=https://waf.example \
RPS=1 \
DURATION=5s \
k6 run k6_run_payloads.js
```

Для обычной работы используйте `run_suite.py`: он создаёт `current_case.json` автоматически во временной директории.

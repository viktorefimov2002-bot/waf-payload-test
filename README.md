# waf-payload-test

Набор инструментов для последовательного тестирования обработки HTTP-тел на WAF. Каждый тест-кейс содержит полностью сформированное байтовое тело, точные заголовки и уникальный идентификатор для корреляции с логами WAF.

## P0-архитектура

- `payload_gen.py` создаёт `payloads.json` с byte-exact телами в Base64.
- `k6_run_payloads.js` запускает только один кейс, выбранный через `PAYLOAD_INDEX`.
- `run_suite.py` последовательно запускает отдельный процесс k6 для каждого кейса и сохраняет журнал и summary.

## Требования

- Python 3.10+
- k6
- опционально `brotli` для генерации Brotli-кейсов

```bash
python3 -m pip install brotli
```

## Генерация

```bash
python3 payload_gen.py --output payloads.json
```

По умолчанию создаются валидные JSON, form-urlencoded, text и octet-stream тела с несколькими charset, BOM, наполнителями, размерами и способами компрессии.

## Пробный запуск одного кейса

```bash
PAYLOAD_INDEX=0 \
TARGET_URL=https://waf.example \
RPS=10 \
DURATION=30s \
k6 run k6_run_payloads.js
```

## Последовательный прогон

```bash
python3 run_suite.py \
  --target https://waf.example \
  --rps 10 \
  --duration 30s \
  --cooldown 5
```

Безопасный короткий smoke-test:

```bash
python3 run_suite.py \
  --target https://waf.example \
  --rps 1 \
  --duration 5s \
  --limit 3 \
  --stop-on-failure
```

Результаты сохраняются в `results/<run-id>/`:

- `run.jsonl` — временная линия активных кейсов;
- `*.summary.json` — summary k6;
- `*.stdout.log` и `*.stderr.log` — вывод отдельного запуска.

Каждый запрос содержит:

- `X-WAF-Test-Run-ID`;
- `X-WAF-Test-Case-ID`;
- `X-WAF-Test-Sequence`.

Эти значения следует добавить в access/debug-логи WAF.

## Важные ограничения P0

P0 исправляет последовательность, byte-exact передачу, Content-Type/Content-Encoding, журналирование и изоляцию кейсов. Расширенные невалидные документы, multipart/XML, сложные структуры и автоматическая минимизация относятся к следующим этапам.

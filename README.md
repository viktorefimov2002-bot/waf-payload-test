# waf-payload-test

Инструмент для воспроизводимого тестирования обработки HTTP request bodies в WAF. Генератор сохраняет byte-exact тело, заголовки, SHA-256, размеры, metadata и уникальный `case_id`, после чего manifest запускается через общий `run_suite.py`.

## Профили

Все наборы создаются одной точкой входа:

```bash
python3 payload_gen_jsonl.py --stress-profile <profile>
```

Основные профили:

| Профиль | Назначение | Основные риски, которые ищем |
|---|---|---|
| `baseline` | Репрезентативное покрытие обычных request-body путей | Ошибки стандартного JSON/form/XML/multipart parsing, charset/BOM, value decoding, single-layer compression |
| `parser-stress` | Нагрузка на parser, allocator и нормализацию | Рост памяти/CPU, глубокие и широкие структуры, длинные имена, множество объектов, escaping, charset faults, multipart edge cases |
| `decompression-stress` | Нагрузка на Content-Encoding decoder | Большие expansion ratio, gzip members, частые flush, stored blocks, nested encodings, ошибки ограничения распакованного размера |

Старые имена `phase1` и `phase2` временно поддерживаются как aliases, но выводят предупреждение:

```text
phase1 -> parser-stress
phase2 -> decompression-stress
```

Справка зависит от профиля:

```bash
python3 payload_gen_jsonl.py --stress-profile baseline --help
python3 payload_gen_jsonl.py --stress-profile parser-stress --help
python3 payload_gen_jsonl.py --stress-profile decompression-stress --help
```

Параметры другого профиля намеренно не принимаются.

## Почему профили не дублируют друг друга

`baseline` и `parser-stress` используют непересекающиеся списки структур. `parser-stress` не является расширенным baseline: он генерирует только специализированные edge-case структуры.

`decompression-stress` строит отдельные compressed streams и маркирует их:

```json
{
  "stress_profile": "decompression-stress",
  "test_dimension": "decompression"
}
```

Обычный однослойный gzip в `baseline` остаётся, потому что это стандартный транспортный вариант. Специализированные members/flush/nesting существуют только в `decompression-stress`.

# Baseline

## Что покрывает

- JSON: `single`, `deep`, `wide`, `array`, `many-fields`, `duplicate-keys`, `truncated`, `trailing-garbage`;
- form-urlencoded: single, many/repeated fields, empty pairs, invalid percent;
- XML: single, deep, wide, attributes, truncated;
- multipart: single, many fields, missing close, LF-only;
- text и octet-stream;
- UTF-8, UTF-16LE/BE, BOM;
- plain, Base64, URL и JSON Unicode escaping;
- обычные gzip, deflate и raw-deflate.

## Широкий coverage-набор

```bash
python3 payload_gen_jsonl.py \
  --stress-profile baseline \
  --output payloads_baseline_coverage.jsonl \
  --path /waf-payload-test/baseline \
  --formats json form xml multipart text octet-stream \
  --sizes 0 1 100 1024 8192 65536 \
  --charsets utf-8 utf-16le utf-16be \
  --compressions none gzip deflate raw-deflate \
  --filler-kinds repeated random-ascii unicode numeric \
  --bom false true \
  --value-encoding-profile recommended \
  --depth 64 \
  --width 256 \
  --fields 512
```

Этот набор широк, поэтому перед запуском проверьте количество строк:

```bash
wc -l payloads_baseline_coverage.jsonl
```

# Parser stress

## Что покрывает

- JSON `deep-wide`, mixed arrays, arrays of objects;
- длинные и многочисленные имена полей;
- form type conflicts;
- escape-heavy JSON/XML/form/text;
- charset mismatch, invalid tails и truncated code units;
- multipart many-short-parts, empty-parts, long name/filename/boundary и boundary collision;
- размеры вокруг типичных границ буферов и лимитов.

## Широкий coverage-набор

```bash
python3 payload_gen_jsonl.py \
  --stress-profile parser-stress \
  --output payloads_parser_stress_coverage.jsonl \
  --path /waf-payload-test/parser-stress \
  --formats json form xml multipart text \
  --sizes 1 16 17 256 257 1024 1025 8192 8193 65536 \
  --charsets utf-8 utf-16le \
  --charset-modes valid mismatch invalid-tail truncated-code-unit \
  --compressions none \
  --filler-kinds repeated random-ascii unicode escape-json escape-xml escape-form \
  --bom false true \
  --value-encoding-profile plain \
  --depth 64 \
  --width 256 \
  --fields 1024 \
  --field-name-lengths 16 256 1024 8192 \
  --multipart-boundary-lengths 70 256 1024 8192
```

Для дополнительной проверки взаимодействия сложного parser input с обычным сжатием создайте отдельный небольшой набор, а не добавляйте gzip ко всей матрице:

```bash
python3 payload_gen_jsonl.py \
  --stress-profile parser-stress \
  --output payloads_parser_stress_gzip.jsonl \
  --formats json xml multipart \
  --sizes 1024 8192 \
  --charsets utf-8 \
  --charset-modes valid \
  --compressions gzip deflate \
  --filler-kinds repeated escape-json escape-xml \
  --bom false \
  --value-encoding-profile plain \
  --depth 32 \
  --width 64 \
  --fields 256 \
  --field-name-lengths 256 1024 \
  --multipart-boundary-lengths 256 1024
```

# Decompression stress

## Что покрывает

- обычные gzip/deflate/raw-deflate/Brotli streams с контролируемым decompressed size;
- concatenated gzip members;
- частые `Z_SYNC_FLUSH`;
- DEFLATE stored blocks;
- repeated и mixed Content-Encoding chains;
- expansion ratio и ограничения размера после распаковки.

## Широкий coverage-набор

```bash
python3 payload_gen_jsonl.py \
  --stress-profile decompression-stress \
  --output payloads_decompression_stress_coverage.jsonl \
  --path /waf-payload-test/decompression-stress \
  --formats json text \
  --algorithms gzip deflate raw-deflate br \
  --variants standard gzip-members sync-flush stored-blocks nested-same nested-mixed \
  --decompressed-sizes 1048576 8388608 67108864 \
  --member-counts 2 8 32 \
  --flush-chunk-sizes 64 1024 16384 \
  --nested-depths 2 3 \
  --max-decompressed-size 67108864 \
  --seed-text A
```

Если Python-модуль `brotli` не установлен, Brotli-кейсы будут пропущены с предупреждением.

# Рекомендуемый порядок запуска

## 1. Проверить manifest без отправки

```bash
python3 run_suite.py \
  --target https://example.invalid \
  --payload-file payloads_baseline_coverage.jsonl \
  --limit 20 \
  --list
```

## 2. Baseline — быстрый sweep

```bash
python3 run_suite.py \
  --mode fast \
  --target https://example.invalid \
  --payload-file payloads_baseline_coverage.jsonl \
  --batch-size 25 \
  --rps 1 \
  --duration 1s \
  --cooldown 1
```

## 3. Parser stress — по одному кейсу

```bash
python3 run_suite.py \
  --mode informative \
  --target https://example.invalid \
  --payload-file payloads_parser_stress_coverage.jsonl \
  --rps 1 \
  --duration 3s \
  --cooldown 3
```

## 4. Decompression stress — сначала с ограничением

```bash
python3 run_suite.py \
  --mode informative \
  --target https://example.invalid \
  --payload-file payloads_decompression_stress_coverage.jsonl \
  --limit 10 \
  --rps 1 \
  --duration 3s \
  --cooldown 5
```

После подтверждения стабильности увеличивайте `--limit`, затем RPS. Не начинайте decompression-stress с `high-rps`.

# Наблюдение за WAF

Во время тестов желательно собирать минимум:

- RSS/PSS процессов WAF;
- CPU по процессам и ядрам;
- OOM, restarts, crashes и core dumps;
- latency и HTTP status;
- active connections и queue length;
- request-body/decompression/parser errors;
- время возврата памяти после завершения кейса.

Сопоставление выполняется по `X-WAF-Test-Case-ID`, `case_id`, SHA-256 и событиям `CASE_START`/`CASE_END`.

# Проверка проекта

```bash
python3 -m py_compile \
  payload_gen.py \
  payload_gen_jsonl.py \
  _structural_profile.py \
  _parser_stress_profile.py \
  _decompression_profile.py \
  _decompression_stress_profile.py
```

```bash
python3 -m pytest -q
```

# Основные компоненты

- `payload_gen_jsonl.py` — единая пользовательская точка генерации;
- `payload_gen.py` — построение структурных документов;
- `_structural_profile.py` — внутренняя логика baseline и legacy phase1;
- `_parser_stress_profile.py` — пользовательский профиль parser-stress;
- `_decompression_profile.py` — внутренняя логика legacy phase2;
- `_decompression_stress_profile.py` — пользовательский профиль decompression-stress;
- `run_suite.py` — orchestrator;
- `k6_run_payloads.js` — k6 scenarios;
- `decode_payload_bodies.py` — извлечение byte-exact тела из manifest.

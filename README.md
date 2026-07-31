# waf-payload-test

Инструмент для воспроизводимого тестирования обработки HTTP request bodies в WAF. Проект генерирует byte-exact тела запросов, сохраняет заголовки, SHA-256, размеры, metadata и уникальный `case_id`, после чего запускает их через общий orchestrator.

## Единая точка генерации

Все пользовательские наборы создаются одной командой:

```bash
python3 payload_gen_jsonl.py --stress-profile <baseline|phase1|phase2>
```

Справка зависит от выбранного профиля:

```bash
python3 payload_gen_jsonl.py --stress-profile baseline --help
python3 payload_gen_jsonl.py --stress-profile phase1 --help
python3 payload_gen_jsonl.py --stress-profile phase2 --help
```

Параметры другого профиля намеренно не принимаются. Например, `--member-counts` доступен только для phase2, а `--field-name-lengths` — только для phase1.

## Модель профилей

Профили не являются последовательными superset-наборами. Каждый отвечает за отдельную подсистему и генерирует собственный класс payloads.

| Профиль | Основная цель | Что генерирует | Что намеренно не генерирует |
|---|---|---|---|
| `baseline` | Репрезентативное покрытие обычных путей обработки body | Базовые JSON/form/XML/multipart/text/octet-stream структуры, типовые charset, value encodings, обычное однослойное gzip/deflate | Длинные имена, boundary stress, charset faults, deep-wide, compression members/flush/nesting |
| `phase1` | Нагрузка на parser, allocator и нормализацию | Только phase1-структуры: deep-wide, mixed arrays/types, длинные имена, escape-heavy, charset mismatch/invalid bytes, multipart edge cases, boundary sizes | Базовые single/deep/wide/array структуры; специализированные decompression streams |
| `phase2` | Нагрузка на декомпрессию | Большой decompressed size, concatenated gzip members, frequent sync flush, stored blocks, nested Content-Encoding | JSON/XML depth/width, длинные имена, charset faults и обычная структурная матрица |

### Почему overlap минимален

- `baseline` и `phase1` используют непересекающиеся списки структур.
- `phase1` по умолчанию использует `compression=none`; обычное сжатие можно включить явно только для проверки взаимодействия parser stress с одним слоем compression.
- `phase2` использует отдельный генератор compressed streams и metadata `test_dimension=decompression`.
- Обычный gzip в baseline — это транспортный вариант типичного запроса, а не decompression stress. В phase2 gzip отличается member count, flush layout, compression level, decompressed size или количеством слоёв.
- Регрессионный тест `tests/test_profile_separation.py` проверяет непересечение structural names и утечку CLI-параметров между профилями.

## Компоненты

- `payload_gen_jsonl.py` — единый profile-aware CLI и потоковая запись JSONL.
- `payload_gen.py` — внутренняя реализация структурных документов.
- `_structural_profile.py` — профильные defaults и scope для baseline/phase1.
- `_decompression_profile.py` — внутренняя реализация phase2.
- `run_suite.py` — orchestrator запуска.
- `k6_run_payloads.js` — сценарии k6.
- `decode_payload_bodies.py` — снятие внешнего Base64-контейнера manifest.

## Требования

- Python 3.10+
- k6 1.3.0 или совместимая версия
- опционально `brotli`

```bash
python3 -m pip install brotli pytest
```

# Baseline

## Назначение

Baseline отвечает на вопрос: как WAF обрабатывает обычную, но достаточно разнообразную матрицу request bodies без специальных стресс-конструкций.

Основное покрытие:

- JSON: `single`, `deep`, `wide`, `array`, `many-fields`, `duplicate-keys`, malformed base cases;
- form-urlencoded: single, many/repeated fields, empty pairs, invalid percent;
- XML: single, deep, wide, attributes, truncated;
- multipart: single, many fields, missing close, LF-only;
- text и octet-stream;
- raw UTF-8/UTF-16, BOM;
- plain/base64/URL/JSON Unicode escaping;
- обычное однослойное gzip/deflate/raw-deflate/Brotli.

Baseline не должен использоваться для предельной нагрузки: его задача — дать опорное поведение WAF и выявить проблемы на типовых путях.

## Пример

```bash
python3 payload_gen_jsonl.py \
  --stress-profile baseline \
  --output payloads_baseline.jsonl \
  --path /test-baseline \
  --formats json form xml multipart text octet-stream \
  --sizes 0 100 1000 10000 \
  --charsets utf-8 utf-16le utf-16be \
  --compressions none gzip deflate \
  --filler-kinds repeated random-ascii unicode \
  --bom false true \
  --value-encoding-profile recommended \
  --depth 64 \
  --width 256 \
  --fields 512
```

# Phase 1: parser and allocator stress

## Назначение

Phase1 проверяет дорогие пути построения и нормализации внутреннего представления запроса:

- большое количество объектов и узлов;
- сочетание глубины и ширины;
- длинные ключи, element names, attribute names, multipart names/filenames;
- escape-heavy значения;
- конфликтующие form-типы;
- charset mismatch и повреждённые code units;
- multipart boundary scanning;
- размеры около типовых границ allocation/limits.

Phase1 генерирует только следующие дополнительные структуры:

- JSON: `deep-wide`, `array-objects`, `array-mixed`, `long-field-name`, `many-long-field-names`, `escape-heavy`;
- form: `long-field-name`, `many-long-field-names`, `mixed-types`, `escape-heavy`;
- XML: `deep-wide`, `long-element-name`, `long-attribute-name`, `escape-heavy`;
- multipart: `many-short-parts`, `empty-parts`, `long-name`, `long-filename`, `long-boundary`, `boundary-collision`;
- text: `escape-heavy`.

Базовые `single`, `deep`, `wide`, `array` и другие baseline-структуры в phase1 повторно не создаются.

## Пример smoke-набора

```bash
python3 payload_gen_jsonl.py \
  --stress-profile phase1 \
  --output payloads_phase1_smoke.jsonl \
  --path /test-phase1 \
  --formats json form xml multipart \
  --sizes 1 1024 \
  --charsets utf-8 \
  --charset-modes valid mismatch \
  --compressions none \
  --filler-kinds repeated escape-json escape-xml escape-form \
  --bom false \
  --value-encoding-profile plain \
  --depth 8 \
  --width 8 \
  --fields 16 \
  --field-name-lengths 16 256 \
  --multipart-boundary-lengths 70 256
```

Для полного набора граничных размеров можно не передавать `--sizes`: phase1 по умолчанию использует `--size-profile boundaries`.

Подробности: `docs/phase1-parser-stress.md`.

# Phase 2: decompression stress

## Назначение

Phase2 проверяет стоимость и устойчивость стадии декомпрессии до передачи тела форматному parser.

Варианты:

- `standard` — обычный валидный compressed stream с контролируемым decompressed size;
- `gzip-members` — concatenated gzip members;
- `sync-flush` — множество маленьких DEFLATE-фрагментов с `Z_SYNC_FLUSH`;
- `stored-blocks` — DEFLATE level 0;
- `nested-same` — повтор одного Content-Encoding;
- `nested-mixed` — смешанные цепочки gzip/deflate/raw-deflate/Brotli.

## Пример smoke-набора

```bash
python3 payload_gen_jsonl.py \
  --stress-profile phase2 \
  --output payloads_phase2_smoke.jsonl \
  --path /test-phase2 \
  --formats json \
  --algorithms gzip deflate raw-deflate \
  --variants standard gzip-members sync-flush stored-blocks nested-same nested-mixed \
  --decompressed-sizes 1048576 8388608 \
  --member-counts 2 8 \
  --flush-chunk-sizes 64 1024 \
  --nested-depths 2
```

По умолчанию максимальный полностью распакованный размер ограничен 256 MiB. Увеличение требует явного `--max-decompressed-size`.

Подробности: `docs/phase2-decompression-stress.md`.

# Запуск наборов

Предварительный просмотр без k6:

```bash
python3 run_suite.py \
  --target https://example.invalid \
  --payload-file payloads_phase1_smoke.jsonl \
  --limit 20 \
  --list
```

## fast

Несколько разных кейсов последовательно выполняются в одном процессе k6. Подходит для baseline и первичного phase1 sweep.

```bash
python3 run_suite.py \
  --mode fast \
  --target https://example.invalid \
  --payload-file payloads_baseline.jsonl \
  --batch-size 25 \
  --rps 1 \
  --duration 1s \
  --cooldown 0
```

## informative

Один кейс запускается в отдельном процессе k6. Это основной режим локализации parser/decompression anomalies и рекомендуемый первый режим для phase2.

```bash
python3 run_suite.py \
  --mode informative \
  --target https://example.invalid \
  --payload-file payloads_phase2_smoke.jsonl \
  --limit 5 \
  --rps 1 \
  --duration 3s \
  --cooldown 3
```

## high-rps

Каждый кейс batch получает отдельный `constant-arrival-rate` scenario. Использовать после одиночной проверки конкретных payloads.

```bash
python3 run_suite.py \
  --mode high-rps \
  --target https://example.invalid \
  --payload-file payloads_phase1_smoke.jsonl \
  --batch-size 5 \
  --rps 100 \
  --duration 5s \
  --cooldown 3 \
  --preallocated-vus 50 \
  --max-vus 200
```

# Рекомендуемая последовательность

1. Запустить `baseline` и сохранить опорные latency/error/resource observations.
2. Запустить `phase1` при низком RPS и определить дорогие structural cases.
3. Запустить `phase2` в `informative` с малых decompressed sizes.
4. Повторить конкретные case IDs с увеличением duration/RPS только после проверки устойчивости.
5. Сопоставлять результаты по `case_id`, `stress_profile`, `profile_scope`, `structure`, `compression_variant` и размерам.

# Проверка кода

```bash
python3 -m py_compile \
  payload_gen.py \
  payload_gen_jsonl.py \
  _structural_profile.py \
  _decompression_profile.py
```

```bash
python3 -m pytest -q
```

Ключевые регрессионные проверки:

- `tests/test_phase1_generator.py`;
- `tests/test_decompression_generator.py`;
- `tests/test_profile_separation.py`.

# Результаты и корреляция

`run_suite.py` сохраняет события:

```text
RUN_START
BATCH_START
CASE_START
CASE_END
BATCH_END
RUN_END
```

Активный кейс и запрос:

```bash
jq . results/<run-id>/active_case.json
jq . results/<run-id>/active_request.json
```

Извлечь byte-exact тело:

```bash
jq -r '.request.body_base64' results/<run-id>/active_request.json |
base64 -d > active-request.body
```

Коды завершения orchestrator:

```text
0    успешно завершено
2    ошибка параметров, файлов или запуска
3    нет подходящих кейсов
130  остановлено через Ctrl+C
```

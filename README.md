# waf-payload-test

Инструмент для воспроизводимого тестирования обработки HTTP request bodies в WAF. Проект генерирует byte-exact запросы с заголовками, SHA-256, размерами, metadata и уникальным `case_id`, после чего запускает их через общий orchestrator.

## Основной интерфейс

Рекомендуемый способ генерации — строгий YAML-конфиг:

```bash
python3 payload_gen_jsonl.py --config configs/baseline-full.yaml
```

Проверка без генерации:

```bash
python3 payload_gen_jsonl.py \
  --config configs/baseline-full.yaml \
  --validate-only
```

Предварительный просмотр выбранного профиля, output и safety limits:

```bash
python3 payload_gen_jsonl.py \
  --config configs/parser-stress-full.yaml \
  --dry-run
```

CLI с `--stress-profile` временно сохранён для обратной совместимости, но новые наборы рекомендуется описывать в YAML.

## Установка

```bash
python3 -m pip install -r requirements.txt
```

Требования:

- Python 3.10+;
- k6 1.3.0 или совместимая версия;
- PyYAML 6.x;
- опционально Python-модуль `brotli` для Brotli cases.

## Профили

Профили являются отдельными тестовыми измерениями, а не последовательными superset-наборами.

| Профиль | Назначение | Основные варианты |
|---|---|---|
| `baseline` | Репрезентативные обычные request bodies | базовые JSON/form/XML/multipart/text/octet-stream, charset, BOM, value encoding, однослойное compression |
| `parser-stress` | Нагрузка на parser, allocator и normalization | deep-wide, mixed types, длинные имена, escape-heavy, charset faults, multipart boundary cases |
| `decompression-stress` | Нагрузка на Content-Encoding decoder | expansion ratio, gzip members, sync flush, stored blocks, nested encodings |

`baseline` и `parser-stress` используют непересекающиеся списки structural cases. Специализированные compressed streams существуют только в `decompression-stress`.

## Готовые конфиги

```text
configs/
├── baseline-smoke.yaml
├── baseline-full.yaml
├── parser-stress-smoke.yaml
├── parser-stress-full.yaml
├── decompression-stress-smoke.yaml
└── decompression-stress-full.yaml
```

### Smoke

Используется для проверки окружения, маршрута, endpoint, k6 и журналирования WAF.

```bash
python3 payload_gen_jsonl.py --config configs/baseline-smoke.yaml
python3 payload_gen_jsonl.py --config configs/parser-stress-smoke.yaml
python3 payload_gen_jsonl.py --config configs/decompression-stress-smoke.yaml
```

### Full

Широкое покрытие большинства практически полезных вариантов каждого профиля.

```bash
python3 payload_gen_jsonl.py --config configs/baseline-full.yaml
python3 payload_gen_jsonl.py --config configs/parser-stress-full.yaml
python3 payload_gen_jsonl.py --config configs/decompression-stress-full.yaml
```

Перед полной генерацией рекомендуется выполнить:

```bash
python3 payload_gen_jsonl.py \
  --config configs/parser-stress-full.yaml \
  --validate-only
```

## Структура YAML

```yaml
version: 1
profile: baseline

output:
  file: payloads/baseline-full.jsonl
  request_path: /waf-test/baseline
  overwrite: false

metadata:
  suite_name: baseline-full
  description: Broad representative coverage
  tags: [baseline, full-coverage]

safety:
  max_cases: 30000
  max_wire_body_size: 67108864
  max_decompressed_size: 67108864

generation:
  # профильные параметры
```

### Общие секции

- `version` — версия схемы, сейчас только `1`;
- `profile` — `baseline`, `parser-stress` или `decompression-stress`;
- `output.file` — путь к JSONL manifest;
- `output.request_path` — HTTP path каждого case;
- `output.overwrite` — разрешение перезаписи существующего manifest;
- `metadata` — suite name, description и tags, добавляемые в каждый case;
- `safety` — жёсткие ограничения генерации;
- `generation` — параметры выбранного профиля.

## Строгая профильная валидация

Параметры другого профиля запрещены. Например, в `baseline` нельзя указать:

```yaml
member_counts: [8]
charset_modes: [mismatch]
field_name_lengths: [8192]
```

Генератор завершится ошибкой вместо молчаливого игнорирования:

```text
ERROR: unsupported option(s) for generation for profile "baseline": charset_modes
```

Это защищает от ситуации, когда пользователь считает, что нужный вариант был создан, хотя параметр фактически не применился.

## Safety limits

```yaml
safety:
  max_cases: 50000
  max_wire_body_size: 134217728
  max_decompressed_size: 134217728
```

Лимиты проверяются:

1. при загрузке конфигурации;
2. по предварительной оценке матрицы;
3. для каждого реально сгенерированного case.

При превышении генерация прерывается, временный файл удаляется, готовый manifest не заменяется.

## Baseline

Назначение — получить опорное поведение WAF на обычных, но разнообразных request bodies.

Покрытие:

- JSON: single, deep, wide, array, many fields, duplicate keys, malformed base cases;
- form-urlencoded: single, many/repeated fields, empty pairs, invalid percent;
- XML: single, deep, wide, attributes, truncated;
- multipart: single, many fields, missing close, LF-only;
- text и octet-stream;
- UTF-8/UTF-16, BOM;
- plain, Base64, URL и JSON Unicode escaping;
- обычное однослойное gzip/deflate/raw-deflate/Brotli.

Полный preset:

```bash
python3 payload_gen_jsonl.py --config configs/baseline-full.yaml
```

Первый запуск:

```bash
python3 run_suite.py \
  --mode fast \
  --target https://example.invalid \
  --payload-file payloads/baseline-full.jsonl \
  --batch-size 25 \
  --rps 1 \
  --duration 1s \
  --cooldown 1
```

## Parser stress

Назначение — искать проблемы рекурсивного parsing, allocation, charset conversion, normalization и multipart scanning.

Покрытие:

- deep-wide JSON/XML;
- mixed arrays и conflicting form types;
- длинные и многочисленные field/tag/attribute names;
- escape-heavy JSON/XML/form/text;
- charset mismatch, invalid tail и truncated code units;
- many short/empty multipart parts;
- длинные и near-collision boundary;
- размеры около типичных границ allocator/parser limits.

Полный preset:

```bash
python3 payload_gen_jsonl.py --config configs/parser-stress-full.yaml
```

Запускать рекомендуется по одному case:

```bash
python3 run_suite.py \
  --mode informative \
  --target https://example.invalid \
  --payload-file payloads/parser-stress-full.jsonl \
  --rps 1 \
  --duration 3s \
  --cooldown 3
```

## Decompression stress

Назначение — искать проблемы Content-Encoding decoder: CPU spikes, memory expansion, hangs, crashes и некорректное завершение потоков.

Покрытие:

- gzip, deflate, raw-deflate и Brotli;
- standard streams;
- concatenated gzip members;
- frequent `Z_SYNC_FLUSH`;
- stored DEFLATE blocks;
- nested same/mixed Content-Encoding;
- decoded bodies 1 MiB, 8 MiB и 64 MiB.

Полный preset:

```bash
python3 payload_gen_jsonl.py --config configs/decompression-stress-full.yaml
```

Первый запуск следует ограничивать:

```bash
python3 run_suite.py \
  --mode informative \
  --target https://example.invalid \
  --payload-file payloads/decompression-stress-full.jsonl \
  --limit 10 \
  --rps 1 \
  --duration 3s \
  --cooldown 5
```

После подтверждения стабильности постепенно увеличиваются `--limit`, decoded size и RPS.

## CLI overrides для YAML

Разрешены только общие overrides:

```bash
python3 payload_gen_jsonl.py \
  --config configs/baseline-full.yaml \
  --output /tmp/baseline.jsonl \
  --request-path /temporary-test
```

Профильные параметры меняются в YAML, а не через CLI.

## Рекомендуемый порядок тестирования

1. Сгенерировать и выполнить три smoke-набора.
2. Выполнить `baseline-full` в режиме `fast`.
3. Повторить подозрительные baseline cases в `informative`.
4. Выполнить `parser-stress-full` при RPS 1 и cooldown.
5. Выполнить `decompression-stress-full` сначала с `--limit`.
6. Для найденных cases отдельно проверять зависимость от RPS и длительности.

## Что наблюдать на WAF

HTTP response сам по себе недостаточен. Следует коррелировать `case_id` с:

- RSS/PSS и возвратом памяти после case;
- CPU user/system time;
- latency и timeout;
- active connections и очередями;
- parser/decompression errors;
- рестартами процесса;
- OOM killer;
- core dumps;
- ростом внутренних argument/object counters.

Для корреляции используются:

```text
X-WAF-Test-Case-ID
case_id
SHA-256
CASE_START
CASE_END
```

## Проверка проекта

```bash
python3 -m py_compile \
  payload_gen.py \
  payload_gen_jsonl.py \
  _config_loader.py \
  _structural_profile.py \
  _parser_stress_profile.py \
  _decompression_profile.py \
  _decompression_stress_profile.py
```

```bash
python3 -m pytest -q
```

## Legacy CLI

Переходный интерфейс пока работает:

```bash
python3 payload_gen_jsonl.py --stress-profile baseline --help
python3 payload_gen_jsonl.py --stress-profile parser-stress --help
python3 payload_gen_jsonl.py --stress-profile decompression-stress --help
```

Aliases `phase1` и `phase2` считаются deprecated.

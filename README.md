# waf-payload-test

Инструмент для воспроизводимого тестирования обработки HTTP request body в WAF.

Проект решает две связанные задачи:

1. генерирует byte-exact HTTP cases в JSONL manifest;
2. запускает эти cases через k6 последовательно или несколькими параллельными lanes.

Каждый case содержит HTTP-метод, путь, заголовки, тело в Base64, SHA-256, размеры, metadata и уникальный `case_id`. Это позволяет однозначно сопоставлять генератор, k6, логи WAF и результаты повторной проверки.

> Используйте проект только против систем, на тестирование которых у вас есть разрешение.

## Возможности

- строгие YAML-конфиги для генерации и запуска;
- профили `baseline`, `parser-stress` и `decompression-stress`;
- JSON, form, XML, multipart, text и octet-stream;
- UTF-8, UTF-16LE, BOM и намеренно некорректные charset-варианты;
- deep/wide structures, repeated fields, длинные имена и multipart boundaries;
- gzip, deflate, raw-deflate и Brotli;
- gzip members, sync flush, stored blocks и nested encodings;
- highly-, medium- и incompressible content profiles;
- пользовательский payload непосредственно в YAML;
- последовательный и параллельный high-RPS запуск;
- общий журнал, отдельные lane-журналы и case-level результаты;
- safety limits на количество cases и размеры тела.

## Структура проекта

```text
waf-payload-test/
├── configs/                    # YAML-конфиги генерации
├── run-configs/                # YAML-конфиги запуска manifests
├── docs/                       # подробная документация
├── modules/                    # внутренние Python-модули
├── payloads/                   # сгенерированные JSONL manifests
├── results/                    # результаты прогонов
├── tests/                      # pytest-тесты
├── payload_gen.py              # генерация структурных bodies
├── payload_gen_jsonl.py        # основная точка генерации manifests
├── run_suite.py                # orchestrator запуска
├── k6_run_payloads.js          # сценарии k6
└── requirements.txt
```

Пользовательские точки входа:

```bash
python3 payload_gen_jsonl.py --config configs/baseline-full.yaml
python3 run_suite.py --config run-configs/high-rps-parallel.yaml
```

Файлы из `payloads/` и `results/` не следует коммитить в Git.

## Требования

- Python 3.11+;
- k6 для запуска трафика;
- Python package `brotli` для Brotli cases.

Установка Python-зависимостей:

```bash
python3 -m pip install -r requirements.txt
```

Опционально для Brotli:

```bash
python3 -m pip install brotli
```

Проверка k6:

```bash
k6 version
```

## Быстрый старт

Проверить проект:

```bash
python3 -m pytest -q
```

Проверить YAML без генерации:

```bash
python3 payload_gen_jsonl.py \
  --config configs/baseline-smoke.yaml \
  --validate-only
```

Сгенерировать smoke manifest:

```bash
python3 payload_gen_jsonl.py \
  --config configs/baseline-smoke.yaml
```

Проверить run-config:

```bash
python3 run_suite.py \
  --config run-configs/baseline-fast.yaml \
  --target https://waf.example \
  --validate-only
```

Запустить ограниченный прогон:

```bash
python3 run_suite.py \
  --config run-configs/baseline-fast.yaml \
  --target https://waf.example
```

## Генерация manifests

Основной интерфейс — строгий YAML-конфиг:

```bash
python3 payload_gen_jsonl.py \
  --config configs/parser-stress-full.yaml
```

Проверка без записи manifest:

```bash
python3 payload_gen_jsonl.py \
  --config configs/parser-stress-full.yaml \
  --validate-only
```

Предпросмотр профиля и safety limits:

```bash
python3 payload_gen_jsonl.py \
  --config configs/parser-stress-full.yaml \
  --dry-run
```

CLI с `--stress-profile` сохранён для обратной совместимости, но новые наборы следует описывать в YAML.

## Пользовательский payload в YAML

Для `baseline` и `parser-stress` payload задаётся в секции `generation`:

```yaml
generation:
  payload: '<acronym id=x tabindex=1 onfocus=prompt(1)></acronym>'
```

Полный пример:

```yaml
version: 1
profile: baseline

output:
  file: payloads/custom-baseline.jsonl
  request_path: /waf-test/custom
  overwrite: false

metadata:
  suite_name: custom-baseline
  description: Custom payload coverage
  tags: [baseline, custom]

safety:
  max_cases: 5000
  max_wire_body_size: 67108864
  max_decompressed_size: 67108864

generation:
  payload: '<acronym id=x tabindex=1 onfocus=prompt(1)></acronym>'
  formats: [json, form, xml, multipart, text]
  sizes: [0, 256, 1024]
  charsets: [utf-8]
  bom: [false]
  filler_kinds: [repeated, random-ascii, unicode]
  value_encoding_profile: recommended
  compressions: [none, gzip]
  structures:
    depth: 16
    width: 32
    fields: 64
```

Упрощённо итоговое значение строится так:

```text
generated filler + payload
```

Поэтому длинный payload может существенно увеличить manifest, особенно в wide, deep-wide и repeated-field структурах.

## Профили генерации

| Профиль | Назначение | Основные варианты |
|---|---|---|
| `baseline` | Обычные пути обработки request body | стандартные форматы, charset, value encoding и однослойное compression |
| `parser-stress` | Parser, allocator и normalization | deep-wide, mixed types, длинные имена, escape-heavy значения, charset faults и multipart edge cases |
| `decompression-stress` | Content-Encoding decoder | expansion ratio, gzip members, sync flush, stored blocks и nested encodings |

`baseline` и `parser-stress` используют разные наборы структур. Специализированные compressed streams создаются только профилем `decompression-stress`.

## Готовые конфиги генерации

```text
configs/
├── baseline-smoke.yaml
├── baseline-full.yaml
├── baseline-large-body.yaml
├── parser-stress-smoke.yaml
├── parser-stress-full.yaml
├── parser-stress-large-body.yaml
├── parser-stress-deep-wide.yaml
├── decompression-stress-smoke.yaml
├── decompression-stress-highly-compressible.yaml
├── decompression-stress-medium-compressible.yaml
└── decompression-stress-incompressible.yaml
```

### Baseline

```bash
python3 payload_gen_jsonl.py --config configs/baseline-smoke.yaml
python3 payload_gen_jsonl.py --config configs/baseline-full.yaml
python3 payload_gen_jsonl.py --config configs/baseline-large-body.yaml
```

`baseline-full` использует размеры значений:

```text
0, 256, 1024
```

Крупные одиночные значения вынесены в `baseline-large-body.yaml`, чтобы не умножать их на широкие структуры.

### Parser stress

```bash
python3 payload_gen_jsonl.py --config configs/parser-stress-smoke.yaml
python3 payload_gen_jsonl.py --config configs/parser-stress-full.yaml
python3 payload_gen_jsonl.py --config configs/parser-stress-large-body.yaml
python3 payload_gen_jsonl.py --config configs/parser-stress-deep-wide.yaml
```

`parser-stress-full` использует:

```yaml
sizes:
  values: [1, 256, 1024]

structures:
  depth: 32
  width: 64
  fields: 1024
  field_name_lengths: [64, 256]
  multipart_boundary_lengths: [70, 256]
```

Экстремальный `depth: 64` / `width: 256` вынесен в `parser-stress-deep-wide.yaml` и использует небольшие per-node значения.

Текущая charset-матрица full-профиля:

```yaml
modes:
  - valid
  - mismatch
  - invalid-tail
  - truncated-code-unit
```

Поэтому ожидаемое соотношение:

```text
25% valid
75% intentionally invalid charset cases
```

`invalid` здесь означает намеренно повреждённый вход для проверки устойчивости parser, а не ошибку генератора.

### Decompression stress

Smoke:

```bash
python3 payload_gen_jsonl.py \
  --config configs/decompression-stress-smoke.yaml
```

Highly compressible:

```bash
python3 payload_gen_jsonl.py \
  --config configs/decompression-stress-highly-compressible.yaml
```

Medium compressible:

```bash
python3 payload_gen_jsonl.py \
  --config configs/decompression-stress-medium-compressible.yaml
```

Incompressible:

```bash
python3 payload_gen_jsonl.py \
  --config configs/decompression-stress-incompressible.yaml
```

Во всех трёх профилях проверяется одинаковая матрица stream-вариантов:

```yaml
formats: [json, text]
algorithms: [gzip, deflate, raw-deflate, br]
variants:
  - standard
  - gzip-members
  - sync-flush
  - stored-blocks
  - nested-same
  - nested-mixed
```

Различается характер данных до сжатия:

| Config | Контент | Размеры после распаковки | Основная цель |
|---|---|---|---|
| `highly-compressible` | повторяющийся текст | 1, 8, 64 MiB | expansion ratio и decompression bomb |
| `medium-compressible` | смешанные повторяющиеся и псевдослучайные блоки | 1, 8, 32 MiB | реалистичная нагрузка на decoder |
| `incompressible` | детерминированный псевдослучайный ASCII | 1, 8 MiB | большие wire bodies и throughput |

Все текущие decompression cases являются валидными compressed streams. Повреждённые потоки следует добавлять отдельным invalid-профилем.

Подробности: `docs/decompression-content-profiles.md`.

## Почему профили разделены

Полное декартово произведение быстро разрастается:

```text
structures × sizes × charsets × charset modes × BOM × fillers × encodings × compression
```

Большой per-node payload одновременно с `depth`, `width` или `fields` может создать один case на сотни MiB и manifest на много GiB.

Поэтому наборы разделены по назначению:

```text
full              — широкое покрытие с умеренными размерами
large-body        — крупные значения с небольшим fan-out
deep-wide         — экстремальный fan-out с маленькими значениями
decompression-*   — отдельные уровни сжимаемости
```

## Run-configs

Готовые конфиги запуска:

```text
run-configs/
├── baseline-fast.yaml
├── parser-informative.yaml
├── decompression-informative.yaml
├── high-rps-recheck.yaml
└── high-rps-parallel.yaml
```

Run-config определяет:

- target URL;
- manifest;
- k6 script;
- режим;
- batch size;
- RPS и duration;
- cooldown;
- filters;
- logging и results directory.

Target можно переопределить через CLI:

```bash
python3 run_suite.py \
  --config run-configs/baseline-fast.yaml \
  --target https://waf.example
```

## Режимы запуска

### `fast`

Последовательная обработка batch внутри одного k6-сценария. Подходит для быстрого первичного прохода с небольшим RPS.

### `informative`

Обычно запускает один case за раз и сохраняет больше информации о запросе. Подходит для диагностики и повторной проверки.

### `high-rps`

Использует `constant-arrival-rate` для каждого case. Может работать последовательно (`lanes: 1`) или параллельно (`lanes > 1`).

## Параллельные lanes

Параллельный режим включается только для `high-rps`:

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

Cases распределяются round-robin:

```text
lane 0: case 0 → case 4 → case 8
lane 1: case 1 → case 5 → case 9
lane 2: case 2 → case 6 → case 10
lane 3: case 3 → case 7 → case 11
```

Внутри одной lane cases идут последовательно. Разные lanes работают одновременно.

`rps` применяется к каждому активному case:

```text
lanes = 4
rps   = 30

максимальная суммарная нагрузка ≈ 120 RPS
```

`max_total_rps` защищает от случайно чрезмерной нагрузки:

```text
lanes × rps <= max_total_rps
```

Готовый запуск:

```bash
python3 run_suite.py \
  --config run-configs/high-rps-parallel.yaml \
  --target https://waf.example
```

Для первого прогона ограничьте selection:

```yaml
selection:
  start_index: 0
  limit: 8
```

При `lanes: 4` это даст две волны по четыре одновременно активных cases.

Подробности: `docs/parallel-case-lanes.md`.

## Рекомендованные параметры

Baseline:

```yaml
lanes: 4
rps: 30
duration: 5s
cooldown: 1
max_total_rps: 120
```

Parser stress:

```yaml
lanes: 2
rps: 20
duration: 5s
cooldown: 1
max_total_rps: 40
```

Decompression с большими распакованными телами следует запускать осторожно:

```yaml
lanes: 1
rps: 1
duration: 5s
cooldown: 3
```

Не запускайте несколько 64 MiB decompression cases при десятках RPS без предварительного расчёта CPU, памяти и сетевой нагрузки.

## Фильтрация cases

Через run-config:

```yaml
selection:
  start_index: 0
  limit: 100
  formats: [json, xml]
  structures: [deep-wide]
  validities: [valid]
```

Поддерживаемые validity values:

```text
valid
invalid
invalid-compression
invalid-charset
```

Пример запуска только корректных parser cases:

```yaml
selection:
  validities: [valid]
```

Намеренно некорректные charset cases:

```yaml
selection:
  validities: [invalid-charset]
```

## Результаты и логирование

Каждый запуск создаёт отдельную директорию:

```text
results/<run-id>/
├── run_config.json
├── run.jsonl
├── case_results.jsonl
├── active_cases.json
├── active_requests/
│   ├── lane-000.json
│   ├── lane-001.json
│   └── ...
├── lanes/
│   ├── lane-000.jsonl
│   ├── lane-001.jsonl
│   └── ...
├── k6-batch-0001.log
├── summary-batch-0001.json
└── payloads.jsonl.gz
```

Назначение:

- `run.jsonl` — общий событийный журнал;
- `case_results.jsonl` — результат завершения каждого case;
- `active_cases.json` — cases, активные в текущий момент;
- `active_requests/lane-XXX.json` — полный активный запрос lane;
- `lanes/lane-XXX.jsonl` — отдельный журнал lane;
- `k6-batch-XXXX.log` — stdout/stderr k6;
- `summary-batch-XXXX.json` — агрегированные k6 metrics;
- `payloads.jsonl.gz` — архив manifest, использованного в запуске.

В запросы добавляются correlation headers:

```text
X-WAF-Test-Case-ID
X-WAF-Test-Run-ID
X-WAF-Test-Sequence
X-WAF-Test-Lane
```

## Что наблюдать на WAF

HTTP status сам по себе недостаточен. Коррелируйте `case_id` и `run_id` с:

- CPU user/system time;
- RSS/PSS и возвратом памяти после case;
- latency, timeout и connection reset;
- active connections и очередями;
- parser/decompression errors;
- HTTP 5xx;
- рестартами процесса;
- OOM killer;
- core dumps;
- ростом внутренних counters;
- состоянием origin.

Для намеренно невалидных parser cases контролируемые `400`, `403`, `415` или `422` могут быть допустимы. Критичны падения, зависания, timeout, connection reset и неконтролируемые `5xx`.

При параллельном запуске сбой может совпасть сразу с несколькими активными cases. Все они должны быть повторно проверены последовательно в `informative` или `high-rps` с `lanes: 1`.

## Safety limits

Параметры другого профиля запрещены. Неизвестная опция вызывает ошибку вместо молчаливого игнорирования.

Safety limits проверяются:

1. при загрузке YAML;
2. по предварительной оценке матрицы;
3. для каждого реально сгенерированного case.

Основные ограничения:

```yaml
safety:
  max_cases: 5000
  max_wire_body_size: 134217728
  max_decompressed_size: 134217728
```

При превышении генерация прерывается, временный файл удаляется, существующий manifest не заменяется.

Не повышайте `max_wire_body_size` только ради прохождения одного чрезмерно размноженного case. Сначала уменьшите structural fan-out или вынесите проверку в focused config.

## Рекомендуемый процесс тестирования

1. Запустить `pytest`.
2. Проверить все YAML через `--validate-only`.
3. Сгенерировать и выполнить smoke-наборы.
4. Выполнить `baseline-full`.
5. Повторить подозрительные cases в `informative`.
6. Выполнить только valid-часть `parser-stress-full`.
7. Отдельно выполнить `invalid-charset` cases.
8. Запускать decompression-профили от highly к incompressible с низким RPS.
9. После последовательного прохода проверить параллельный режим на небольшом `limit`.
10. Для failure window повторно проверить все активные cases с `lanes: 1`.
11. Для найденного проблемного измерения создать узкий boundary config.

## Проверка проекта

Полный набор тестов:

```bash
python3 -m pytest -q
```

Проверка Python syntax:

```bash
python3 -m py_compile \
  payload_gen.py \
  payload_gen_jsonl.py \
  run_suite.py \
  modules/config_loader.py \
  modules/validated_config.py \
  modules/structural_profile.py \
  modules/parser_stress_profile.py \
  modules/decompression_profile.py \
  modules/decompression_stress_profile.py
```

Проверка всех generation-конфигов:

```bash
for config in configs/*.yaml; do
  python3 payload_gen_jsonl.py \
    --config "$config" \
    --validate-only || exit 1
done
```

Проверка run-config:

```bash
python3 run_suite.py \
  --config run-configs/high-rps-parallel.yaml \
  --target https://waf.example \
  --validate-only
```

## Обновление рабочей ветки

```bash
git fetch origin
git switch feature/parallel-case-lanes
git pull
```

При наличии локальных изменений:

```bash
git stash push -m "local changes"
git pull
git stash list
```

Не применяйте stash автоматически, если в нём лежат старые версии YAML-конфигов: сначала просмотрите изменения через `git stash show -p`.

## Legacy CLI

```bash
python3 payload_gen_jsonl.py --stress-profile baseline --help
python3 payload_gen_jsonl.py --stress-profile parser-stress --help
python3 payload_gen_jsonl.py --stress-profile decompression-stress --help
```

Aliases `phase1` и `phase2` считаются deprecated.

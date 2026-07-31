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

CLI с `--stress-profile` временно сохранён для обратной совместимости, но новые наборы следует описывать в YAML.

## Установка

```bash
python3 -m pip install -r requirements.txt
```

Опционально для Brotli:

```bash
python3 -m pip install brotli
```

## Профили

Профили являются отдельными тестовыми измерениями, а не последовательными superset-наборами.

| Профиль | Назначение | Основные варианты |
|---|---|---|
| `baseline` | Обычные пути обработки request body | базовые JSON/form/XML/multipart/text/octet-stream, charset, value encoding, однослойное compression |
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

Используется для проверки окружения, endpoint, k6 и журналирования WAF.

```bash
python3 payload_gen_jsonl.py --config configs/baseline-smoke.yaml
python3 payload_gen_jsonl.py --config configs/parser-stress-smoke.yaml
python3 payload_gen_jsonl.py --config configs/decompression-stress-smoke.yaml
```

### Optimized full

Full-конфиги используют оптимизированное покрытие вместо полного декартова произведения всех параметров.

Ожидаемый масштаб:

- `baseline-full`: около 3900 cases;
- `parser-stress-full`: около 3600 cases;
- `decompression-stress-full`: менее 200 cases.

```bash
python3 payload_gen_jsonl.py --config configs/baseline-full.yaml
python3 payload_gen_jsonl.py --config configs/parser-stress-full.yaml
python3 payload_gen_jsonl.py --config configs/decompression-stress-full.yaml
```

Перед генерацией:

```bash
python3 payload_gen_jsonl.py \
  --config configs/parser-stress-full.yaml \
  --validate-only
```

## Почему матрицы сокращены

Основной источник чрезмерного количества cases — декартово произведение:

```text
structures × sizes × charsets × charset modes × BOM × fillers × encodings × compression
```

Практический набор не должен проверять каждую комбинацию, если она не открывает новый путь обработки WAF.

Оптимизированные presets сохраняют:

- все основные форматы;
- все структуры соответствующего профиля;
- типичный небольшой body;
- крупный body;
- пустой или минимальный body там, где это важно;
- Unicode и обычный ASCII;
- ключевые charset fault modes;
- обычное сжатие и специализированные decompression variants.

При этом исключены повторяющиеся комбинации, например прогон каждого filler через каждый BOM, каждый charset и каждый compression.

## Baseline full

Покрывает все baseline-структуры:

- JSON: single, deep, wide, array, many fields, duplicate keys, malformed base cases;
- form-urlencoded: single, many/repeated fields, empty pairs, invalid percent;
- XML: single, deep, wide, attributes, truncated;
- multipart: single, many fields, missing close, LF-only;
- text и octet-stream.

Оптимизированные измерения:

```yaml
generation:
  sizes: [0, 1024, 65536]
  charsets: [utf-8, utf-16le]
  bom: [false]
  filler_kinds: [repeated, random-ascii, unicode]
  compressions: [none, gzip, deflate]
```

Почему выбраны эти размеры:

- `0` — пустые и минимальные документы;
- `1024` — обычный небольшой запрос;
- `65536` — крупный request body и типичная граница буферов.

Почему исключён `raw-deflate`: он использует тот же HTTP `Content-Encoding: deflate`, а специализированная работа с raw DEFLATE уже проверяется в `decompression-stress`.

Генерация:

```bash
python3 payload_gen_jsonl.py --config configs/baseline-full.yaml
```

Запуск:

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

## Parser stress full

Сохраняет все специальные структуры:

- deep-wide JSON/XML;
- mixed arrays и conflicting form types;
- длинные и многочисленные field/tag/attribute names;
- escape-heavy JSON/XML/form/text;
- charset mismatch, invalid tail и truncated code units;
- many short/empty multipart parts;
- long и collision-like multipart boundary.

Оптимизированные измерения:

```yaml
generation:
  sizes:
    values: [1, 1024, 65536]
  charsets:
    declared: [utf-8, utf-16le]
    modes: [valid, mismatch, invalid-tail, truncated-code-unit]
    bom: [false]
  filler_kinds: [repeated, unicode, escape-json, escape-xml, escape-form]
  structures:
    field_name_lengths: [256, 8192]
    multipart_boundary_lengths: [70, 8192]
```

Здесь сохранены:

- минимальный размер;
- обычный небольшой размер;
- крупный размер;
- нормальная и экстремальная длина имени;
- стандартная и экстремальная длина boundary;
- все charset fault modes.

Удалены соседние значения `15/16/17`, `255/256/257` и другие ±1-пары. Их полезно добавлять только после обнаружения конкретного порога или при тестировании известного лимита WAF.

Генерация:

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

## Decompression stress full

Покрывает:

- gzip, deflate, raw-deflate и Brotli;
- standard streams;
- concatenated gzip members;
- frequent `Z_SYNC_FLUSH`;
- stored DEFLATE blocks;
- nested same/mixed Content-Encoding;
- decoded bodies 1 MiB, 8 MiB и 64 MiB.

Этот набор уже небольшой по количеству cases, поэтому его матрица существенно не сокращалась. Каждый case здесь значительно тяжелее structural cases.

```bash
python3 payload_gen_jsonl.py --config configs/decompression-stress-full.yaml
```

Первый запуск:

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

## Когда использовать дополнительные граничные значения

Полные ±1-наборы следует использовать не в первом широком sweep, а на втором диагностическом этапе.

Например, если проблема проявилась около 64 KiB, создаётся копия config с:

```yaml
sizes:
  values: [65535, 65536, 65537]
```

То же относится к:

- длине field name;
- multipart boundary;
- depth;
- width;
- fields;
- decompressed size.

Это позволяет сначала найти проблемное измерение, а затем точно локализовать порог без десятков тысяч лишних запросов.

## Строгая профильная валидация

Параметры другого профиля запрещены. Например, в `baseline` нельзя указать decompression или parser-only поля.

Неизвестная опция приводит к ошибке вместо молчаливого игнорирования.

## Safety limits

Лимиты проверяются:

1. при загрузке конфигурации;
2. по предварительной оценке матрицы;
3. для каждого реально сгенерированного case.

При превышении генерация прерывается, временный файл удаляется, готовый manifest не заменяется.

## Рекомендуемый порядок тестирования

1. Выполнить три smoke-набора.
2. Выполнить `baseline-full` в режиме `fast`.
3. Повторить подозрительные baseline cases в `informative`.
4. Выполнить `parser-stress-full` при RPS 1 и cooldown.
5. Выполнить `decompression-stress-full` сначала с `--limit`.
6. Для найденного измерения создать узкий boundary config с ±1 значениями.
7. Для найденных cases отдельно проверить зависимость от RPS и длительности.

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
  _validated_config.py \
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

# waf-payload-test

Инструмент для воспроизводимого тестирования обработки HTTP request bodies в WAF. Генератор создаёт byte-exact payload cases с заголовками, SHA-256, размерами, metadata и уникальным `case_id`, после чего manifest запускается через общий orchestrator.

## Структура проекта

```text
waf-payload-test/
├── configs/                    # готовые YAML-наборы тестов
├── docs/                       # подробная документация по профилям
├── modules/                    # внутренние Python-модули
│   ├── __init__.py
│   ├── config_loader.py
│   ├── validated_config.py
│   ├── structural_profile.py
│   ├── parser_stress_profile.py
│   ├── decompression_profile.py
│   └── decompression_stress_profile.py
├── payloads/                   # сгенерированные JSONL manifests
├── tests/                      # pytest-тесты
├── payload_gen.py              # построение структурных payload bodies
├── payload_gen_jsonl.py        # основная точка генерации manifest
├── run_suite.py                # orchestrator запуска
├── k6_run_payloads.js          # сценарии k6
└── requirements.txt
```

Файлы в `modules/` являются внутренней реализацией. Пользовательский интерфейс проекта остаётся в корне:

```bash
python3 payload_gen_jsonl.py --config configs/baseline-full.yaml
python3 run_suite.py --help
```

Сгенерированные manifests складываются в `payloads/` и не должны коммититься в Git.

## Установка

```bash
python3 -m pip install -r requirements.txt
```

Опционально для Brotli:

```bash
python3 -m pip install brotli
```

## Основной интерфейс

Генерация выполняется через строгий YAML-конфиг:

```bash
python3 payload_gen_jsonl.py \
  --config configs/baseline-full.yaml
```

Проверка без генерации:

```bash
python3 payload_gen_jsonl.py \
  --config configs/baseline-full.yaml \
  --validate-only
```

Предпросмотр профиля, output и safety limits:

```bash
python3 payload_gen_jsonl.py \
  --config configs/parser-stress-full.yaml \
  --dry-run
```

CLI с `--stress-profile` временно сохранён для обратной совместимости, но новые наборы следует описывать в YAML.

## Профили

| Профиль | Назначение | Основные варианты |
|---|---|---|
| `baseline` | Обычные пути обработки request body | базовые JSON/form/XML/multipart/text/octet-stream, charset, value encoding, однослойное compression |
| `parser-stress` | Нагрузка на parser, allocator и normalization | deep-wide, mixed types, длинные имена, escape-heavy, charset faults, multipart boundary cases |
| `decompression-stress` | Нагрузка на Content-Encoding decoder | expansion ratio, gzip members, sync flush, stored blocks, nested encodings |

`baseline` и `parser-stress` используют непересекающиеся списки структур. Специализированные compressed streams существуют только в `decompression-stress`.

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

```bash
python3 payload_gen_jsonl.py --config configs/baseline-smoke.yaml
python3 payload_gen_jsonl.py --config configs/parser-stress-smoke.yaml
python3 payload_gen_jsonl.py --config configs/decompression-stress-smoke.yaml
```

### Optimized full

Ожидаемый масштаб:

- `baseline-full`: около 3900 cases;
- `parser-stress-full`: около 3600 cases;
- `decompression-stress-full`: менее 200 cases.

```bash
python3 payload_gen_jsonl.py --config configs/baseline-full.yaml
python3 payload_gen_jsonl.py --config configs/parser-stress-full.yaml
python3 payload_gen_jsonl.py --config configs/decompression-stress-full.yaml
```

Результаты создаются здесь:

```text
payloads/baseline-smoke.jsonl
payloads/baseline-full.jsonl
payloads/parser-stress-smoke.jsonl
payloads/parser-stress-full.jsonl
payloads/decompression-stress-smoke.jsonl
payloads/decompression-stress-full.jsonl
```

## Почему full-матрицы сокращены

Полное декартово произведение быстро разрастается:

```text
structures × sizes × charsets × charset modes × BOM × fillers × encodings × compression
```

Оптимизированные presets сохраняют:

- все основные форматы;
- все структуры соответствующего профиля;
- минимальный, типичный и крупный body;
- ASCII и Unicode;
- ключевые charset fault modes;
- стандартное и специализированное сжатие.

Повторяющиеся комбинации удалены. Значения вида `65535/65536/65537` следует добавлять на втором диагностическом этапе после обнаружения конкретного проблемного диапазона.

## Запуск manifests

Baseline:

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

Parser stress:

```bash
python3 run_suite.py \
  --mode informative \
  --target https://example.invalid \
  --payload-file payloads/parser-stress-full.jsonl \
  --rps 1 \
  --duration 3s \
  --cooldown 3
```

Decompression stress:

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

## Строгая профильная валидация

Параметры другого профиля запрещены. Неизвестная опция приводит к ошибке вместо молчаливого игнорирования.

Safety limits проверяются:

1. при загрузке конфигурации;
2. по предварительной оценке матрицы;
3. для каждого реально сгенерированного case.

При превышении генерация прерывается, временный файл удаляется, существующий manifest не заменяется.

## Рекомендуемый процесс

1. Проверить все конфиги через `--validate-only`.
2. Выполнить три smoke-набора.
3. Выполнить `baseline-full`.
4. Повторить подозрительные cases в `informative`.
5. Выполнить `parser-stress-full` при RPS 1 и cooldown.
6. Выполнить `decompression-stress-full` сначала с `--limit`.
7. Для найденного измерения создать узкий boundary config.
8. Для конкретного case проверить зависимость от RPS и длительности.

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
  modules/config_loader.py \
  modules/validated_config.py \
  modules/structural_profile.py \
  modules/parser_stress_profile.py \
  modules/decompression_profile.py \
  modules/decompression_stress_profile.py
```

```bash
python3 -m pytest -q
```

Проверка всех YAML:

```bash
for config in configs/*.yaml; do
  python3 payload_gen_jsonl.py \
    --config "$config" \
    --validate-only || exit 1
done
```

## Legacy CLI

```bash
python3 payload_gen_jsonl.py --stress-profile baseline --help
python3 payload_gen_jsonl.py --stress-profile parser-stress --help
python3 payload_gen_jsonl.py --stress-profile decompression-stress --help
```

Aliases `phase1` и `phase2` считаются deprecated.

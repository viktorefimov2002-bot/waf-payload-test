# waf-payload-test

Набор инструментов для последовательного тестирования обработки HTTP-тел на WAF. Каждый кейс содержит полностью сформированное byte-exact тело, точные заголовки и уникальный идентификатор для корреляции с логами WAF.

## Архитектура

- `payload_gen.py` создаёт `payloads.json` с byte-exact телами в Base64.
- `k6_run_payloads.js` запускает один кейс, выбранный через `PAYLOAD_INDEX`.
- `run_suite.py` последовательно запускает отдельный процесс k6 для каждого кейса и ведёт компактный журнал.

Suite не определяет состояние Lua-машины и не пытается автоматически подтверждать проблему. Мониторинг выполняется отдельно на WAF. При обнаружении проблемы оператор вручную останавливает suite через `Ctrl+C`.

## Требования

- Python 3.10+
- k6
- опционально `brotli` для генерации Brotli-кейсов

```bash
python3 -m pip install brotli
```

## Генерация

Минимальная команда:

```bash
python3 payload_gen.py --output payloads.json
```

По умолчанию используются только обычные значения (`plain`). Рекомендуемые дополнительные варианты кодирования включаются явно через:

```bash
--value-encoding-profile recommended
```

### Покрываемые структуры

- JSON: одиночное поле, глубокая вложенность, широкие объекты, массивы, множество полей, duplicate keys, усечённый документ и trailing garbage.
- Form URL encoded: одиночное поле, множество полей, повторяющиеся ключи, пустые пары и некорректные percent-последовательности.
- XML: одиночный элемент, глубокая вложенность, множество sibling-элементов, большое число атрибутов и усечённый документ.
- Multipart: одиночная часть, множество частей, отсутствующий closing boundary и LF вместо CRLF.
- Text и octet-stream: простые byte-exact тела для базового сравнения.

### Варианты кодирования значений

Рекомендуемый профиль применяет только осмысленные для конкретного формата комбинации:

| Формат | Варианты |
|---|---|
| JSON | `plain`, `base64`, `url`, `json-unicode-escape` |
| Form URL encoded | `plain`, `double-url`, `base64` |
| XML | `plain`, `base64`, `url` |
| Multipart | `plain`, `base64` |
| Text | `plain`, `base64`, `url` |
| Octet-stream | `plain`, `base64` |

Особенности:

- `body_base64` в manifest используется только для byte-exact хранения тела. Перед отправкой k6 декодирует его обратно в исходные байты.
- `base64` как `value_encoding` означает, что само значение поля реально преобразовано в Base64 до сериализации документа.
- `url` percent-кодирует значение перед помещением в JSON, XML или text.
- `double-url` сначала percent-кодирует значение, после чего form-сериализация кодирует символ `%` ещё раз. Например `%2F` становится `%252F`.
- `json-unicode-escape` создаёт JSON с последовательностями `\uXXXX` вместо непосредственных Unicode-символов.
- Для специальной структуры `invalid-percent` используется только `plain`, поскольку её тело формируется как заранее заданная некорректная percent-последовательность.

Включить рекомендуемый профиль:

```bash
python3 payload_gen.py \
  --output payloads.json \
  --value-encoding-profile recommended
```

Можно указать отдельные варианты вручную:

```bash
python3 payload_gen.py \
  --output payloads.json \
  --formats json xml text \
  --value-encodings plain base64 url
```

Неподдерживаемые для конкретного формата комбинации при явном выборе не создаются. Для запуска по всем форматам удобнее использовать профиль `recommended`.

### Оптимальная выборка

Для первого полного sweep рекомендуется:

```bash
python3 payload_gen.py \
  --output payloads.json \
  --path /test-endpoint \
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

Эта команда создаёт **3504 кейса**:

```text
73 совместимых пары structure/value_encoding
× 3 filler
× 4 размера
× 4 compression
= 3504
```

### Полная штатная выборка

Текущие значения по умолчанию с дополнительным рекомендуемым профилем:

```bash
python3 payload_gen.py \
  --output payloads-full.json \
  --value-encoding-profile recommended
```

Создаётся **7740 кейсов** без повреждённых compressed streams.

Без `--value-encoding-profile recommended` прежняя plain-only выборка содержит **5040 кейсов**.

### Основные параметры генератора

```bash
python3 payload_gen.py \
  --sizes 0 100 1000 10000 \
  --formats json form xml multipart text octet-stream \
  --charsets utf-8 utf-16le utf-16be \
  --compressions none gzip deflate raw-deflate \
  --filler-kinds repeated random-ascii unicode numeric \
  --value-encoding-profile recommended \
  --depth 64 \
  --width 256 \
  --fields 512
```

Для добавления контролируемо повреждённых compressed streams:

```bash
python3 payload_gen.py \
  --output payloads.json \
  --include-corrupt-compression
```

Добавляются режимы `truncated`, `bad-tail` и `bitflip` для каждой сжатой версии.

Каждый кейс содержит:

- `logical_size` — размер исходного логического значения;
- `serialized_size` — размер документа после сериализации и charset;
- `wire_body_size` — фактический размер HTTP-тела;
- `expansion_ratio`;
- SHA-256 тела;
- `metadata.value_encoding`;
- `metadata.encoded_value_utf8_size`;
- metadata по формату, структуре, charset, BOM, валидности, глубине, ширине и числу полей.

## Пробный запуск одного кейса

```bash
PAYLOAD_INDEX=0 \
PAYLOAD_FILE=./payloads.json \
TARGET_URL=https://waf.example \
RPS=1 \
DURATION=5s \
k6 run k6_run_payloads.js
```

## Последовательный прогон

```bash
python3 run_suite.py \
  --target https://waf.example \
  --payload-file payloads.json \
  --rps 1 \
  --duration 5s \
  --cooldown 2
```

Suite проходит все выбранные кейсы независимо от HTTP-статусов, exit code k6 и локальных метрик. Автоматических retry и автоматической остановки нет.

Безопасный короткий smoke-test:

```bash
python3 payload_gen.py \
  --output payloads.json \
  --formats json form xml multipart \
  --sizes 0 100 \
  --charsets utf-8 \
  --compressions none gzip \
  --filler-kinds repeated unicode \
  --bom false \
  --value-encoding-profile recommended \
  --depth 8 \
  --width 8 \
  --fields 8

python3 run_suite.py \
  --target https://waf.example \
  --payload-file payloads.json \
  --rps 1 \
  --duration 5s \
  --limit 10
```

## Ручная остановка

При обнаружении проблемы мониторингом WAF нажмите `Ctrl+C`.

Orchestrator:

1. отправит `SIGINT` текущему процессу k6;
2. запишет событие `RUN_INTERRUPTED` в журнал;
3. сохранит полный текущий запрос;
4. сохранит временные stdout, stderr и summary текущего кейса;
5. оставит в `active_case.json` последний активный case ID.

## Артефакты результата

Для штатного прогона:

```text
results/<run-id>/
├── run_config.json
├── run.jsonl
├── active_case.json
└── payloads.json.gz
```

- `run_config.json` — параметры запуска, путь к архивному manifest и SHA-256 исходного manifest.
- `run.jsonl` — временная линия `RUN_START`, `CASE_START`, `CASE_END`, `RUN_END` или `RUN_INTERRUPTED`.
- `active_case.json` — текущий либо последний активный кейс.
- `payloads.json.gz` — неизменяемая сжатая копия manifest конкретного прогона.

Полные summary, stdout и stderr штатных кейсов удаляются. Компактные метрики переносятся в `CASE_END`.

При ручном прерывании дополнительно создаётся:

```text
results/<run-id>/interrupted/
├── request.json
├── k6-summary.json
├── stdout.log
└── stderr.log
```

`request.json` содержит полный byte-exact кейс, включая заголовки, `body_base64`, SHA-256 и metadata.

## Поиск активного запроса по времени

`run.jsonl` содержит точные временные границы:

```json
{"event":"CASE_START","timestamp":"2026-07-28T08:15:31Z","index":42,"case_id":"case-000043-json-deep-base64-utf-8-gzip-valid"}
{"event":"CASE_END","timestamp":"2026-07-28T08:16:01Z","index":42,"case_id":"case-000043-json-deep-base64-utf-8-gzip-valid"}
```

Каждый HTTP-запрос также содержит:

- `X-WAF-Test-Run-ID`;
- `X-WAF-Test-Case-ID`;
- `X-WAF-Test-Sequence`.

## Поиск и воспроизведение кейса по case_id

Используйте `payloads.json.gz` из нужной run-директории.

Посмотреть полный кейс:

```bash
gzip -cd results/<run-id>/payloads.json.gz |
jq '.[] | select(.id == "case-000043-json-deep-base64-utf-8-gzip-valid")'
```

Извлечь точное бинарное тело:

```bash
gzip -cd results/<run-id>/payloads.json.gz |
jq -r '.[] | select(.id == "case-000043-json-deep-base64-utf-8-gzip-valid") | .body_base64' |
base64 -d > request.body
```

Найти индекс:

```bash
gzip -cd results/<run-id>/payloads.json.gz |
jq 'to_entries[]
    | select(.value.id == "case-000043-json-deep-base64-utf-8-gzip-valid")
    | .key'
```

Распаковать manifest и повторить кейс:

```bash
gzip -cd results/<run-id>/payloads.json.gz > reproduced-payloads.json

PAYLOAD_INDEX=42 \
PAYLOAD_FILE=./reproduced-payloads.json \
TARGET_URL=https://waf.example \
RPS=1 \
DURATION=30s \
k6 run k6_run_payloads.js
```

## Контроль объёма корпуса

Полная декартова комбинация параметров может создать большой manifest. Для первичного sweep ограничивайте `sizes`, `charsets`, `compressions`, `filler-kinds`, `depth`, `width` и `fields`.

Повреждённые документы и compressed streams намеренно могут получать 400, 403, 413, 415 или другие ответы. Suite не трактует их как подтверждение проблемы WAF.

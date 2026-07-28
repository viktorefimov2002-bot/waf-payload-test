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

```bash
python3 payload_gen.py --output payloads.json
```

По умолчанию создаются JSON, form-urlencoded, XML, multipart, text и octet-stream тела с несколькими charset, BOM, наполнителями, размерами и способами компрессии.

### Покрываемые структуры

- JSON: одиночное поле, глубокая вложенность, широкие объекты, массивы, множество полей, duplicate keys, усечённый документ и trailing garbage.
- Form URL encoded: одиночное поле, множество полей, повторяющиеся ключи, пустые пары и некорректные percent-последовательности.
- XML: одиночный элемент, глубокая вложенность, множество sibling-элементов, большое число атрибутов и усечённый документ.
- Multipart: одиночная часть, множество частей, отсутствующий closing boundary и LF вместо CRLF.
- Text и octet-stream: простые byte-exact тела для базового сравнения.

### Основные параметры генератора

```bash
python3 payload_gen.py \
  --sizes 0 100 1000 10000 \
  --formats json form xml multipart text octet-stream \
  --charsets utf-8 utf-16le utf-16be \
  --compressions none gzip deflate raw-deflate \
  --filler-kinds repeated random-ascii unicode numeric \
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

Добавляются режимы `truncated`, `bad-tail` и `bitflip`.

Каждый кейс содержит:

- `logical_size`;
- `serialized_size`;
- `wire_body_size`;
- `expansion_ratio`;
- SHA-256 тела;
- metadata по формату, структуре, charset, валидности, глубине, ширине и числу полей.

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

Suite проходит все выбранные кейсы независимо от HTTP-статусов, exit code k6 и локальных метрик. Автоматических retry и автоматической остановки нет.

Безопасный короткий smoke-test:

```bash
python3 payload_gen.py \
  --output payloads.json \
  --formats json form xml multipart \
  --sizes 0 100 \
  --charsets utf-8 \
  --compressions none gzip \
  --depth 8 \
  --width 8 \
  --fields 8

python3 run_suite.py \
  --target https://waf.example \
  --rps 1 \
  --duration 5s \
  --limit 10
```

## Ручная остановка

При обнаружении проблемы мониторингом WAF нажмите:

```text
Ctrl+C
```

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
- `payloads.json.gz` — неизменяемая сжатая копия manifest конкретного прогона. Она содержит все заголовки, `body_base64`, SHA-256 и metadata каждого кейса.

Для каждого завершённого кейса из временного k6 summary в `CASE_END` переносятся только компактные метрики:

- число HTTP-запросов;
- `http_req_failed`;
- p95 и max latency;
- `dropped_iterations`;
- checks rate;
- объём отправленных и полученных данных.

Полные summary, stdout и stderr штатных кейсов удаляются. Поэтому число файлов не растёт пропорционально числу кейсов.

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
{"event":"CASE_START","timestamp":"2026-07-28T08:15:31Z","index":42,"case_id":"case-000043-json-deep-utf-8-gzip-valid"}
{"event":"CASE_END","timestamp":"2026-07-28T08:16:01Z","index":42,"case_id":"case-000043-json-deep-utf-8-gzip-valid"}
```

Если событие на WAF произошло между этими отметками, активным был указанный `case_id`.

Каждый HTTP-запрос также содержит:

- `X-WAF-Test-Run-ID`;
- `X-WAF-Test-Case-ID`;
- `X-WAF-Test-Sequence`.

Эти значения рекомендуется добавить в access/debug-логи WAF.

## Поиск и воспроизведение кейса по case_id

Используйте `payloads.json.gz` из нужной run-директории, а не текущий рабочий `payloads.json`. Это гарантирует, что повторяется именно manifest данного прогона.

Посмотреть полный кейс:

```bash
gzip -cd results/<run-id>/payloads.json.gz |
jq '.[] | select(.id == "case-000043-json-deep-utf-8-gzip-valid")'
```

Сохранить кейс отдельно:

```bash
gzip -cd results/<run-id>/payloads.json.gz |
jq '.[] | select(.id == "case-000043-json-deep-utf-8-gzip-valid")' \
  > request.json
```

Извлечь точное бинарное тело запроса:

```bash
gzip -cd results/<run-id>/payloads.json.gz |
jq -r '.[] | select(.id == "case-000043-json-deep-utf-8-gzip-valid") | .body_base64' |
base64 -d > request.body
```

Найти индекс кейса:

```bash
gzip -cd results/<run-id>/payloads.json.gz |
jq 'to_entries[]
    | select(.value.id == "case-000043-json-deep-utf-8-gzip-valid")
    | .key'
```

Для повторного запуска сначала распакуйте архивный manifest:

```bash
gzip -cd results/<run-id>/payloads.json.gz > reproduced-payloads.json
```

Затем передайте найденный индекс в k6:

```bash
PAYLOAD_INDEX=42 \
PAYLOAD_FILE=./reproduced-payloads.json \
TARGET_URL=https://waf.example \
RPS=1 \
DURATION=30s \
k6 run k6_run_payloads.js
```

Перед воспроизведением можно сверить SHA-256 тела из `run.jsonl` с полем `sha256` в архивном manifest.

## Контроль объёма корпуса

Полная декартова комбинация параметров может создать большой manifest. Для первичного sweep рекомендуется ограничивать `sizes`, `charsets`, `compressions`, `depth`, `width` и `fields`.

Повреждённые документы и compressed streams намеренно могут получать 400, 403, 413, 415 или другие ответы. Suite не трактует их как подтверждение проблемы WAF.

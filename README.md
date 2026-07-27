# waf-payload-test

Набор инструментов для последовательного тестирования обработки HTTP-тел на WAF. Каждый тест-кейс содержит полностью сформированное байтовое тело, точные заголовки и уникальный идентификатор для корреляции с логами WAF.

## Архитектура

- `payload_gen.py` создаёт `payloads.json` с byte-exact телами в Base64.
- `k6_run_payloads.js` запускает только один кейс, выбранный через `PAYLOAD_INDEX`.
- `run_suite.py` последовательно запускает отдельный процесс k6 для каждого кейса, выполняет health-check и сохраняет воспроизводимые артефакты.

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

- JSON: одиночное поле, глубокая вложенность, широкие объекты, массивы, множество полей, дублирующиеся ключи, усечённый документ, мусор после корректного документа.
- Form URL encoded: одиночное поле, множество полей, повторяющиеся ключи, пустые пары, некорректные percent-последовательности.
- XML: одиночный элемент, глубокая вложенность, множество sibling-элементов, большое число атрибутов, усечённый документ.
- Multipart: одиночная часть, множество частей, отсутствующий closing boundary, LF вместо CRLF.
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

Для добавления контролируемо повреждённых gzip/deflate/Brotli потоков:

```bash
python3 payload_gen.py \
  --output payloads.json \
  --include-corrupt-compression
```

Для каждого сжатого варианта будут добавлены режимы:

- `truncated` — поток обрезан примерно наполовину;
- `bad-tail` — повреждён хвост и checksum;
- `bitflip` — изменён байт в середине потока.

Каждый кейс содержит:

- `logical_size` — размер логического значения в UTF-8;
- `serialized_size` — размер сформированного документа до компрессии;
- `wire_body_size` — фактический размер HTTP-тела;
- `expansion_ratio` — отношение распакованного размера к передаваемому;
- `sha256` — контрольную сумму тела;
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
  --health-url https://waf.example/health \
  --rps 10 \
  --duration 30s \
  --cooldown 5 \
  --retry-suspicious 1
```

### Что считается подозрительным

Кейс помечается как suspicious, если выполняется хотя бы одно условие:

- k6 завершился с ненулевым exit code;
- отсутствует или не читается k6 summary;
- `http_req_failed` достиг порога `--suspicious-status-rate`;
- появились `dropped_iterations`;
- health-check после кейса не прошёл.

Подозрительный кейс автоматически повторяется указанное число раз. Между попытками используется `--retry-cooldown`.

Пример более строгого запуска:

```bash
python3 run_suite.py \
  --target https://waf.example \
  --health-url https://waf.example/health \
  --health-expected 200 204 403 \
  --health-retries 5 \
  --health-timeout 3 \
  --retry-suspicious 2 \
  --retry-cooldown 15 \
  --suspicious-status-rate 0.01 \
  --stop-on-failure
```

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
  --health-url https://waf.example/health \
  --rps 1 \
  --duration 5s \
  --limit 10 \
  --retry-suspicious 1 \
  --stop-on-failure
```

## Артефакты результата

Результаты сохраняются в `results/<run-id>/`:

- `run_config.json` — полный конфиг запуска и SHA-256 manifest;
- `run.jsonl` — временная линия health-check, стартов и окончаний кейсов;
- `active_cases.json` — текущий и последние активные case ID;
- `suspicious_cases.jsonl` — подозрительные попытки вместе с полным описанием кейса;
- `last_suspicious_case.json` — последний подозрительный кейс, результат и недавняя история;
- `*.summary.json` — summary каждой попытки k6;
- `*.stdout.log` и `*.stderr.log` — вывод отдельной попытки.

При падении WAF первым делом следует открыть:

```bash
cat results/<run-id>/active_cases.json
cat results/<run-id>/last_suspicious_case.json
```

Каждый запрос содержит:

- `X-WAF-Test-Run-ID`;
- `X-WAF-Test-Case-ID`;
- `X-WAF-Test-Sequence`.

Эти значения следует добавить в access/debug-логи WAF.

## Контроль объёма корпуса

Полная декартова комбинация параметров может создать очень большой manifest. Для первичного sweep рекомендуется ограничивать `sizes`, `charsets`, `compressions`, `depth`, `width` и `fields`, а подозрительные классы затем повторять отдельным точечным прогоном.

Повреждённые документы и compressed streams намеренно могут приводить к ответам 400, 413 или 415. Для данного теста это штатный результат, если worker WAF остаётся жив и память возвращается к базовому уровню.

# waf-payload-test

Набор инструментов для последовательного тестирования обработки HTTP-тел на WAF. Каждый тест-кейс содержит полностью сформированное байтовое тело, точные заголовки и уникальный идентификатор для корреляции с логами WAF.

## Архитектура

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
  --rps 10 \
  --duration 30s \
  --cooldown 5
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
  --rps 1 \
  --duration 5s \
  --limit 10 \
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

## Контроль объёма корпуса

Полная декартова комбинация параметров может создать очень большой manifest. Для первичного sweep рекомендуется ограничивать `sizes`, `charsets`, `compressions`, `depth`, `width` и `fields`, а подозрительные классы затем повторять отдельным точечным прогоном.

Повреждённые документы и compressed streams намеренно могут приводить к ответам 400, 413 или 415. Для данного теста это штатный результат, если worker WAF остаётся жив и память возвращается к базовому уровню.

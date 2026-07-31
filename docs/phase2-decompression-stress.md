# Phase 2: decompression stress

Второй этап проверяет обработку WAF сжатых HTTP request bodies. Он вынесен в отдельный генератор `decompression_gen.py`, чтобы тяжёлые декомпрессионные кейсы не смешивались с обычным структурным sweep.

## Что генерируется

### standard

Обычный валидный поток выбранного алгоритма:

- gzip;
- zlib-wrapped deflate;
- raw DEFLATE с HTTP-заголовком `Content-Encoding: deflate`;
- Brotli, если установлен модуль `brotli`.

### gzip-members

Одно HTTP-тело содержит несколько последовательно соединённых gzip members. После полной распаковки получается исходный документ.

Управление:

```bash
--member-counts 2 8 32
```

### sync-flush

DEFLATE-поток формируется небольшими фрагментами с `Z_SYNC_FLUSH` после каждого фрагмента.

Управление:

```bash
--flush-chunk-sizes 64 1024 16384
```

Применяется к gzip, deflate и raw-deflate.

### stored-blocks

DEFLATE level 0: данные хранятся практически без сжатия, но всё равно проходят через decompression parser.

### nested-same

Одно и то же кодирование применяется несколько раз:

```http
Content-Encoding: gzip, gzip
```

Управление:

```bash
--nested-depths 2 3
```

### nested-mixed

Генерируются цепочки:

```text
gzip → deflate
deflate → gzip
gzip → raw-deflate
```

При наличии Brotli дополнительно:

```text
gzip → br
br → gzip
```

Порядок в `Content-Encoding` соответствует порядку применения преобразований.

## Metadata

Каждый кейс содержит:

```json
{
  "test_dimension": "decompression",
  "compression_variant": "gzip-members",
  "content_encoding_chain": ["gzip"],
  "compression_layers": 1,
  "decompressed_size": 8388608,
  "compressed_size": 8192,
  "expansion_ratio": 1024.0,
  "gzip_member_count": 8
}
```

Для sync-flush добавляется `flush_chunk_size`, для nested-вариантов — `nested_depth`.

## Защитный предел

По умолчанию нельзя запросить распакованное тело больше 256 MiB:

```bash
--max-decompressed-size 268435456
```

Для увеличения лимита его необходимо изменить явно. Это защищает от случайного создания чрезмерно больших manifests и нагрузочных запросов.

## Минимальный smoke-набор

```bash
python3 decompression_gen.py \
  --output payloads_decompression_smoke.jsonl \
  --formats json \
  --algorithms gzip deflate raw-deflate \
  --variants standard gzip-members sync-flush stored-blocks nested-same nested-mixed \
  --decompressed-sizes 1048576 8388608 \
  --member-counts 2 8 \
  --flush-chunk-sizes 64 1024 \
  --nested-depths 2
```

## Запуск

Начинать рекомендуется с одного запроса в секунду:

```bash
python3 run_suite.py \
  --mode informative \
  --target https://example.invalid \
  --payload-file payloads_decompression_smoke.jsonl \
  --rps 1 \
  --duration 3s \
  --cooldown 3
```

После проверки стабильности можно использовать `high-rps`, но сначала следует ограничить выборку через `--structure`, `--compression` или `--limit`.

## Более тяжёлый набор

```bash
python3 decompression_gen.py \
  --output payloads_decompression.jsonl \
  --formats json text \
  --algorithms gzip deflate raw-deflate br \
  --variants standard gzip-members sync-flush stored-blocks nested-same nested-mixed \
  --decompressed-sizes 1048576 8388608 67108864 \
  --member-counts 2 8 32 \
  --flush-chunk-sizes 64 1024 16384 \
  --nested-depths 2 3
```

Brotli-кейсы пропускаются с предупреждением, если Python-модуль `brotli` не установлен.

## Проверка файлов

```bash
python3 -m py_compile decompression_gen.py
python3 -m pytest -q tests/test_decompression_generator.py
```

## Важное ограничение

Генератор создаёт только тело и корректный `Content-Encoding`. Он не управляет сетевой фрагментацией, chunked transfer encoding или несовпадающим Content-Length. Эти варианты относятся к будущему raw HTTP модулю.

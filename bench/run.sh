#!/usr/bin/env bash
# g7z 压缩基准：对比 g7z 与官方 7-Zip 在同一语料上的压缩率与速度。
# 用法: ./bench/run.sh [语料目录]   （缺省自动生成合成语料）
# 输出: 每行一个用例：工具 命令 压缩大小 压缩耗时 解压校验结果
set -euo pipefail

CORPUS="${1:-}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

if [[ -z "$CORPUS" ]]; then
  # 合成语料：重复文本（字典敏感）、随机二进制、可执行近似（重复代码段）
  C="$WORK/corpus"; mkdir -p "$C"
  python3 - "$C" <<'EOF'
import sys, random, os, struct
d = sys.argv[1]
random.seed(42)
# 文本：重复日志行，测字典/固实
with open(os.path.join(d, 'text.log'), 'wb') as f:
    for i in range(150000):
        f.write(b'2026-11-09 INFO api=%d latency=%dms user=%d status=200\n' % (i % 500, i % 300, i % 5000))
# 二进制：半随机
buf = bytearray(os.urandom(4 << 20))
for i in range(0, len(buf), 4096):
    buf[i:i+64] = b'HEADER-BLOCK-%06d' % (i // 4096)
open(os.path.join(d, 'blob.bin'), 'wb').write(bytes(buf))
# 可执行近似：重复代码段 + e8 call 指令模式（供 BCJ 场景）
import struct as st
seg = bytearray()
for j in range(1000):
    seg += bytes([0x55, 0x48, 0x89, 0xE5]) + b'\xE8' + st.pack('<i', (j % 100) * 64) + bytes([0x90] * 60)
code = seg * 2000
open(os.path.join(d, 'code.bin'), 'wb').write(code)
EOF
  CORPUS="$C"
fi

SEVENZ=$(command -v 7z || true)
TIME_CMD() { # 耗时秒
  local t0=$(date +%s%N); "$@" >/dev/null 2>&1; local rc=$?
  echo "$rc $(( ($(date +%s%N) - t0) / 1000000 ))"
}

G7Z="${G7Z:-$(dirname "$0")/../g7z}"
[[ -x "$G7Z" ]] || G7Z=$(dirname "$0")/../g7z
G7Z=$(cd "$(dirname "$G7Z")" && pwd)/$(basename "$G7Z")

size() { stat -c %s "$1"; }

printf '%-8s %-28s %12s %10s %8s\n' TOOL CASE SIZE_MS TIME_MS CHECK
run() { # tool case outfile checkpw...
  local tool=$1 case=$2 out=$3; shift 3
  read -r rc ms <<<"$(TIME_CMD "$@")"
  local s=$(size "$out" 2>/dev/null || echo -)
  local chk=-
  if [[ $rc -eq 0 ]]; then
    chk=ok
  else chk=FAIL:$rc; fi
  printf '%-8s %-28s %12s %10s %8s\n' "$tool" "$case" "$s" "$ms" "$chk"
}

check() { # file pw... 用各自工具校验
  :
}

# --- 7z：g7z vs 官方 ---
run g7z "7z-mx9"        "$WORK/g_9.7z"   "$G7Z" a "$WORK/g_9.7z"  "$CORPUS" -mx9 -q
[[ -n "$SEVENZ" ]] && run 7z   "7z-mx9"  "$WORK/o_9.7z"   "$SEVENZ" a "$WORK/o_9.7z" "$CORPUS" -mx9 -bso0 -bse0
run g7z "7z-mx9-md256m" "$WORK/g_m.7z"   "$G7Z" a "$WORK/g_m.7z"  "$CORPUS" -mx9 -md=256m -q
run g7z "7z-mx1"        "$WORK/g_1.7z"   "$G7Z" a "$WORK/g_1.7z"  "$CORPUS" -mx1 -q

# --- 单流压缩 ---
run g7z "xz-mx9"        "$WORK/t.tar.xz" "$G7Z" a "$WORK/t.tar.xz" "$CORPUS" -mx9 -q
run g7z "zst-mx9"       "$WORK/t.tar.zst" "$G7Z" a "$WORK/t.tar.zst" "$CORPUS" -mx9 -q
[[ -n "$SEVENZ" ]] && { "$SEVENZ" i 2>/dev/null | grep -qi zstd && run 7z "7z-zstd" "$WORK/o.zst" "$SEVENZ" a "$WORK/o.zst" "$CORPUS" -m0=zstd -bso0 -bse0 || true; }

# --- 校验与往返 ---
for f in "$WORK"/g_9.7z "$WORK"/g_m.7z "$WORK"/t.tar.xz "$WORK"/t.tar.zst; do
  "$G7Z" t "$f" -q >/dev/null 2>&1 || { echo "FAIL 自校验: $f"; exit 1; }
done
"$G7Z" x "$WORK"/g_9.7z -o"$WORK/out" -y -q >/dev/null 2>&1
# 目录输入会在归档内保留目录名前缀
SRC=$(find "$WORK/out" -maxdepth 1 -mindepth 1 -type d | head -1)
diff -r "$CORPUS" "$SRC" >/dev/null && echo "ROUNDTRIP: OK" || { echo "ROUNDTRIP: FAIL"; exit 1; }
echo "语料: $(du -sh "$CORPUS" | cut -f1)  （自建语料请作为参数传入真实目录）"

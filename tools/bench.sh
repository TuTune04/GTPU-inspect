#!/usr/bin/env bash
# Đo nhiều cấu hình gtpu-inspect, in bảng Markdown (median của RUNS lần).
#
#   tools/bench.sh FILE.pcap "BIN [ARGS]" ["BIN [ARGS]" ...]
#   RUNS=7 tools/bench.sh bench/data/big.pcap "build-rel/gtpu-inspect" \
#       "build-rel/gtpu-inspect -w 2" "/tmp/v1/gtpu-inspect -w 2"
#
# Các cấu hình chạy XEN KẼ theo vòng (vòng 1: A B C, vòng 2: A B C...) để
# laptop nóng lên / hạ xung ảnh hưởng đều mọi cấu hình, thay vì dồn vào
# cấu hình chạy sau cùng.
#
# Cột:
#   wall  thời gian cả process (ms)
#   cpu   user + sys của cả process (ms); > wall nghĩa là nhiều core cùng bận
#   Mpps  2 số cuối dòng "pipeline:" trên stderr nếu có, ngược lại tính từ
#         wall và tổng gói in ở stdout ("Packets: N")
set -euo pipefail

if [ $# -lt 2 ]; then
  sed -n '2,7p' "$0" >&2
  exit 2
fi
file=$1
shift
runs=${RUNS:-5}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat "$file" > /dev/null   # đưa file vào page cache trước khi đo

for ((r = 0; r < runs; r++)); do
  for ((i = 1; i <= $#; i++)); do
    cmd=${!i}
    # shellcheck disable=SC2086  # cmd cố ý được tách theo khoảng trắng
    t=$( { TIMEFORMAT='%R %U %S'; time $cmd "$file" > "$tmp/out" 2> "$tmp/err"; } 2>&1 )
    read -r real user sys <<< "$t"
    pkts=$(sed -n 's/^Packets: *\([0-9]*\).*/\1/p' "$tmp/out")
    mpps=$(sed -n 's/^pipeline:.*(\([0-9.]*\) Mpps).*/\1/p' "$tmp/err")
    if [ -z "$mpps" ]; then
      mpps=$(awk -v p="$pkts" -v t="$real" 'BEGIN { printf "%.2f", p / t / 1e6 }')
    fi
    awk -v a="$real" -v b="$user" -v c="$sys" -v m="$mpps" \
      'BEGIN { printf "%d %d %s\n", a * 1000, (b + c) * 1000, m }' >> "$tmp/$i"
  done
done

median() { sort -n | awk '{ v[NR] = $1 } END { print v[int((NR + 1) / 2)] }'; }

echo "| Cấu hình | wall (ms) | cpu (ms) | Mpps |"
echo "|---|---|---|---|"
for ((i = 1; i <= $#; i++)); do
  printf '| `%s` | %s | %s | %s |\n' "${!i}" \
    "$(cut -d' ' -f1 "$tmp/$i" | median)" \
    "$(cut -d' ' -f2 "$tmp/$i" | median)" \
    "$(cut -d' ' -f3 "$tmp/$i" | median)"
done

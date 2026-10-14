#!/bin/sh
# Chạy một lệnh và chỉ báo lỗi nếu nó chết vì signal (segfault, abort...).
# Exit code bình thường khác 0 (ví dụ file pcap hỏng) vẫn được coi là pass.
"$@"
rc=$?
if [ "$rc" -ge 128 ]; then
  echo "run_no_crash: '$*' chết vì signal $((rc - 128))" >&2
  exit 1
fi
exit 0

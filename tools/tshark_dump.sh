#!/bin/sh
# In mỗi gói một dòng bằng tshark để đối chiếu với output của gtpu-inspect
# và với file .expected tương ứng.
#   tools/tshark_dump.sh tests/data/gtpu_5g_ext.pcap
# Thêm field bằng biến EXTRA, ví dụ tìm tên field QFI bằng:
#   tshark -G fields | grep -i qos_flow
#   EXTRA="-e <tên field>" tools/tshark_dump.sh file.pcap
set -eu
[ $# -ge 1 ] || { echo "usage: $0 file.pcap" >&2; exit 2; }
# shellcheck disable=SC2086
tshark -r "$1" -T fields -E header=y \
  -e frame.number -e ip.src -e ip.dst -e gtp.message -e gtp.teid \
  -e gtp.seq_number -e _ws.expert.message ${EXTRA:-}

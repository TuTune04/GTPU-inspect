- Không viết code trong src/parser.c, src/gtpu.c, src/session_table.c, src/ring.c, src/mempool.c.
  Với các file này chỉ được giải thích khái niệm, gợi ý hướng, và review code tôi viết.
- Được phép viết: CMakeLists.txt, CI, script trong tools/, khung test.
- Chuẩn code: C11, -Wall -Wextra -Werror, không ép kiểu con trỏ buffer sang struct header.
# 抗量子威胁判定引擎 pqc-judge — 构建脚本
# 用法：make           编译 pqc-judge 与单元测试
#       make check     运行单元测试
#       make clean     清理
# 说明：核心模块不依赖 openssl 开发库；证书解析默认调用 openssl CLI，
#       并内置纯 DER 解析作为回退（-m der）。

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c99 -D_GNU_SOURCE
LDFLAGS ?=

SRC = src/main.c src/threat_judge.c src/oid_db.c src/cert_parser.c
SRC_LIB = src/threat_judge.c src/oid_db.c src/cert_parser.c

all: pqc-judge test_judge

pqc-judge: $(SRC) src/threat_judge.h src/oid_db.h src/cert_parser.h
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)

test_judge: test/test_judge.c $(SRC_LIB) src/threat_judge.h src/oid_db.h src/cert_parser.h
	$(CC) $(CFLAGS) -Isrc -o $@ test/test_judge.c $(SRC_LIB) $(LDFLAGS)

check: test_judge pqc-judge
	./test_judge

clean:
	rm -f pqc-judge test_judge

.PHONY: all check clean

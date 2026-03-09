# EVERPARSE := ../../../everparse/bin/everparse/everparse.sh  # only needed for 'generate' target
EVERPARSE_INC := generated

CC := gcc
CFLAGS := -Wall -Wextra -Werror -std=gnu99 -I. -Igenerated -I$(EVERPARSE_INC) -DEVERPARSE_NO_COPY

GEN_DIR := generated
GEN_SRCS := $(GEN_DIR)/ArithMul.c $(GEN_DIR)/ArithMulWrapper.c \
            $(GEN_DIR)/ArithAdd.c $(GEN_DIR)/ArithAddWrapper.c \
            $(GEN_DIR)/SubTest.c $(GEN_DIR)/SubTestWrapper.c \
            $(GEN_DIR)/SubTest16.c $(GEN_DIR)/SubTest16Wrapper.c \
            $(GEN_DIR)/ModbusCheck.c $(GEN_DIR)/ModbusCheckWrapper.c
TEST_SRCS := arith_test_harness.c
TARGET := arith_test

.PHONY: all generate build test clean

all: test

generate:
	$(EVERPARSE) --batch ArithMul.3d
	$(EVERPARSE) --batch ArithAdd.3d
	$(EVERPARSE) --batch SubTest.3d
	$(EVERPARSE) --batch SubTest16.3d
	$(EVERPARSE) --batch ModbusCheck.3d
	@mkdir -p $(GEN_DIR)
	mv -f ArithMul.c ArithMul.h ArithMulWrapper.c ArithMulWrapper.h \
	      ArithAdd.c ArithAdd.h ArithAddWrapper.c ArithAddWrapper.h \
	      SubTest.c SubTest.h SubTestWrapper.c SubTestWrapper.h \
	      SubTest16.c SubTest16.h SubTest16Wrapper.c SubTest16Wrapper.h \
	      ModbusCheck.c ModbusCheck.h ModbusCheckWrapper.c ModbusCheckWrapper.h \
	      EverParse.h EverParseEndianness.h $(GEN_DIR)/

build: $(TARGET)

$(TARGET): $(TEST_SRCS) $(GEN_SRCS) $(wildcard $(GEN_DIR)/*.h)
	$(CC) $(CFLAGS) -o $@ $(TEST_SRCS) $(GEN_SRCS)

test: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

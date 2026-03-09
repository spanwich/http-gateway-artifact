# EVERPARSE := ../../../everparse/bin/everparse/everparse.sh  # only needed for 'generate' target
EVERPARSE_INC := generated

CC := gcc
CFLAGS := -Wall -Wextra -Werror -std=gnu99 -I. -Igenerated -I$(EVERPARSE_INC) -DEVERPARSE_NO_COPY

GEN_DIR := generated
GEN_SRCS := $(GEN_DIR)/RangeTest.c $(GEN_DIR)/RangeTestWrapper.c
TEST_SRCS := range_test_harness.c
TARGET := range_test

.PHONY: all generate build test clean

all: test

generate: RangeTest.3d
	$(EVERPARSE) --batch RangeTest.3d
	@mkdir -p $(GEN_DIR)
	mv -f RangeTest.c RangeTest.h RangeTestWrapper.c RangeTestWrapper.h \
	      EverParse.h EverParseEndianness.h $(GEN_DIR)/

build: $(TARGET)

$(TARGET): $(TEST_SRCS) $(GEN_SRCS) $(wildcard $(GEN_DIR)/*.h)
	$(CC) $(CFLAGS) -o $@ $(TEST_SRCS) $(GEN_SRCS)

test: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

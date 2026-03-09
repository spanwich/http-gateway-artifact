# EVERPARSE := ../../../everparse/bin/everparse/everparse.sh  # only needed for 'generate' target
EVERPARSE_INC := generated

CC := gcc
CFLAGS := -Wall -Wextra -Werror -std=gnu99 -I. -Igenerated -I$(EVERPARSE_INC) -DEVERPARSE_NO_COPY

GEN_DIR := generated
GEN_SRCS := $(GEN_DIR)/BitTestA.c $(GEN_DIR)/BitTestAWrapper.c \
            $(GEN_DIR)/BitTestB.c $(GEN_DIR)/BitTestBWrapper.c \
            $(GEN_DIR)/BitTestC.c $(GEN_DIR)/BitTestCWrapper.c
TEST_SRCS := bit_test_harness.c
TARGET := bit_test

.PHONY: all generate build test clean

all: test

generate:
	$(EVERPARSE) --batch BitTestA.3d
	$(EVERPARSE) --batch BitTestB.3d
	$(EVERPARSE) --batch BitTestC.3d
	@mkdir -p $(GEN_DIR)
	mv -f BitTestA.c BitTestA.h BitTestAWrapper.c BitTestAWrapper.h \
	      BitTestB.c BitTestB.h BitTestBWrapper.c BitTestBWrapper.h \
	      BitTestC.c BitTestC.h BitTestCWrapper.c BitTestCWrapper.h \
	      EverParse.h EverParseEndianness.h $(GEN_DIR)/

build: $(TARGET)

$(TARGET): $(TEST_SRCS) $(GEN_SRCS) $(wildcard $(GEN_DIR)/*.h)
	$(CC) $(CFLAGS) -o $@ $(TEST_SRCS) $(GEN_SRCS)

test: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

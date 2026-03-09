# EVERPARSE := ../../../everparse/bin/everparse/everparse.sh  # only needed for 'generate' target
EVERPARSE_INC := generated

CC     := gcc
CFLAGS := -Wall -Wextra -Werror -std=gnu99 -I. -Igenerated -I$(EVERPARSE_INC) -DEVERPARSE_NO_COPY

GEN_SRCS := generated/PartAccess8.c generated/PartAccess8Wrapper.c \
            generated/UnivRate.c generated/UnivRateWrapper.c \
            generated/MonoAccess16.c generated/MonoAccess16Wrapper.c
TARGET   := partition_test

.PHONY: all build test clean

all: test

build: $(TARGET)

$(TARGET): partition_harness.c $(GEN_SRCS) $(wildcard generated/*.h)
	$(CC) $(CFLAGS) -o $@ partition_harness.c $(GEN_SRCS)

test: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

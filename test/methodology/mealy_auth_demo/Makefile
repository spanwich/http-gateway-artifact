# EVERPARSE := ../../everparse/bin/everparse/everparse.sh  # only needed for 'generate' target
EVERPARSE_INC := generated

CC := gcc
CFLAGS := -Wall -Wextra -Werror -std=gnu99 -I. -Igenerated -I$(EVERPARSE_INC) -DEVERPARSE_NO_COPY

GEN_DIR := generated
GEN_SRCS := $(GEN_DIR)/MealyAuth.c $(GEN_DIR)/MealyAuthWrapper.c
APP_SRCS := mealy_app.c
TEST_SRCS := mealy_test.c
TARGET := mealy_test

.PHONY: all generate build test clean

all: test

generate: MealyAuth.3d
	$(EVERPARSE) --batch MealyAuth.3d
	@mkdir -p $(GEN_DIR)
	mv -f MealyAuth.c MealyAuth.h MealyAuthWrapper.c MealyAuthWrapper.h \
	      EverParse.h EverParseEndianness.h $(GEN_DIR)/
	rm -f *.fst *.fsti *.checked *.krml *.rsp

build: $(TARGET)

$(TARGET): $(TEST_SRCS) $(APP_SRCS) $(GEN_SRCS) $(wildcard $(GEN_DIR)/*.h)
	$(CC) $(CFLAGS) -o $@ $(TEST_SRCS) $(APP_SRCS) $(GEN_SRCS)

test: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

# EVERPARSE := ../../../everparse/bin/everparse/everparse.sh  # only needed for 'generate' target
EVERPARSE_INC := generated

CC := gcc
CFLAGS := -Wall -Wextra -Werror -std=gnu99 -I. -Igenerated -I$(EVERPARSE_INC) -DEVERPARSE_NO_COPY

GEN_DIR := generated
GEN_SRCS := $(GEN_DIR)/RbacPolicy.c $(GEN_DIR)/RbacPolicyWrapper.c
APP_SRCS := rbac_app.c
TEST_SRCS := rbac_test.c
TARGET := rbac_test

.PHONY: all generate build test clean

all: test

generate: RbacPolicy.3d
	$(EVERPARSE) --batch RbacPolicy.3d
	@mkdir -p $(GEN_DIR)
	mv -f RbacPolicy.c RbacPolicy.h RbacPolicyWrapper.c RbacPolicyWrapper.h \
	      EverParse.h EverParseEndianness.h $(GEN_DIR)/
	rm -f *.fst *.fsti *.checked *.krml *.rsp

build: $(TARGET)

$(TARGET): $(TEST_SRCS) $(APP_SRCS) $(GEN_SRCS) $(wildcard $(GEN_DIR)/*.h)
	$(CC) $(CFLAGS) -o $@ $(TEST_SRCS) $(APP_SRCS) $(GEN_SRCS)

test: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

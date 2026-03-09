CC := gcc
CFLAGS := -Wall -Wextra -Werror -std=gnu99 -I. -Igenerated -DEVERPARSE_NO_COPY

GEN_SRCS := generated/RbacPolicy.c generated/RbacPolicyWrapper.c
APP_SRCS := pipeline.c session.c mock_extractor.c
TEST_SRCS := ../test/production/pipeline_test.c

.PHONY: all build test clean

all: test

build: pipeline_test

pipeline_test: $(TEST_SRCS) $(APP_SRCS) $(GEN_SRCS) $(wildcard generated/*.h)
	$(CC) $(CFLAGS) -o $@ $(TEST_SRCS) $(APP_SRCS) $(GEN_SRCS)

test: pipeline_test
	./pipeline_test

clean:
	rm -f pipeline_test

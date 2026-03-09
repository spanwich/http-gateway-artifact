CC := gcc
CFLAGS := -Wall -Wextra -Werror -std=gnu99 -I../../specs -I../../specs/generated -DEVERPARSE_NO_COPY

GEN_SRCS := ../../specs/generated/RbacPolicy.c ../../specs/generated/RbacPolicyWrapper.c
APP_SRCS := ../../specs/pipeline.c ../../specs/session.c ../../specs/mock_extractor.c

.PHONY: all build test clean

all: test

build: pipeline_test

pipeline_test: pipeline_test.c $(APP_SRCS) $(GEN_SRCS)
	$(CC) $(CFLAGS) -o $@ $< $(APP_SRCS) $(GEN_SRCS)

test: pipeline_test
	./pipeline_test

clean:
	rm -f pipeline_test

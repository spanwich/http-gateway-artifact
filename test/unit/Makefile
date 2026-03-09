CC := gcc
CFLAGS := -Wall -Wextra -Werror

.PHONY: all test clean

all: test

test_rate_limiter: test_rate_limiter.c
	$(CC) $(CFLAGS) -o $@ $<

test: test_rate_limiter
	./test_rate_limiter

clean:
	rm -f test_rate_limiter

CC := gcc
CFLAGS := -m32 -std=gnu99 -g -O0 -no-pie -fno-stack-protector -fno-PIE -fno-pie -fno-stack-check -ldl
ALL := ex1

ex1: ex1.c
	$(CC) $(CFLAGS) -o $@ $< -ldl

all: $(ALL)

clean:
	rm -f $(ALL)

.PHONY: all clean
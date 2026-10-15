# gitpp-c — 7th fold port in C99

CC = gcc
CFLAGS = -O2 -Wall
LDFLAGS = -lm

gitpp: gitpp.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

.PHONY: test
test: gitpp
	@./gitpp /path/to/records.json --at task-c

.PHONY: clean
clean:
	rm -f gitpp

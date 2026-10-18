# gitpp-c -- 7th fold port in C99

CC = gcc
# -std=gnu99 SPECIFICALLY, not -std=c99. fmemopen is a GNU extension: under
# -std=c99 it is implicitly declared as returning int, so the FILE* built from
# it is garbage, and the binary exits 0 having emitted nothing at all. That is
# a silent failure, not a build error.
CFLAGS = -std=gnu99 -O2 -Wall
LDFLAGS = -lm

gitpp: gitpp.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# The suite #includes gitpp.c, so it sees the port's own static internals
# (record_leaf, parse_record, json_parse) rather than reimplementing them.
test_gitpp: tests/test_gitpp.c gitpp.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

.PHONY: test
test: gitpp test_gitpp
	@./test_gitpp
	@./tests/cli.sh ./gitpp

.PHONY: clean
clean:
	rm -f gitpp test_gitpp

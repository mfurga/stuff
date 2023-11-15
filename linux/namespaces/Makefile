CFLAGS :=
CFLAGS += -Wall -Wextra
CFLAGS += -no-pie  # disable ASLR

all:
	gcc $(CFLAGS) ns.c -o ns

.PHONY: clean
clean:
	rm ns

CFLAGS :=
CFLAGS += -no-pie  # disable ASLR

all:
	gcc $(CFLAGS) prog.c -o prog
	gcc $(CFLAGS) ptrace.c -o ptrace

.PHONY: clean
clean:
	rm prog ptrace

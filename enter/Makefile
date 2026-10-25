CFLAGS ?= -O2 -Wall -Wextra -Werror
amosjail-enter: amosjail-enter.c
	$(CC) $(CFLAGS) -o $@ $< -lsandbox -lbsm
clean:
	rm -f amosjail-enter

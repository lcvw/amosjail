#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
int main(void) {
    char c = '#';
    int r = ioctl(0, TIOCSTI, &c);
    printf("TIOCSTI on stdin tty: %s\n", r == 0 ? "INJECTED" : strerror(errno));
    return 0;
}

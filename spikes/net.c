// net: try a set of connections; one line each.
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
static int tconnect(int fd, void *a, socklen_t l) {
    fcntl(fd, F_SETFL, O_NONBLOCK);
    if (connect(fd, a, l) == 0) return 0;
    if (errno != EINPROGRESS) return -1;
    struct pollfd p = {fd, POLLOUT, 0};
    if (poll(&p, 1, 2000) != 1) { errno = ETIMEDOUT; return -1; }
    int e; socklen_t el = sizeof e; getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &el);
    if (e) { errno = e; return -1; }
    return 0;
}
static void tcp(const char *ip, int port) {
    struct sockaddr_storage ss = {0}; socklen_t l; int fam;
    if (strchr(ip, ':')) { struct sockaddr_in6 *s = (void *)&ss; s->sin6_family = fam = AF_INET6; s->sin6_port = htons(port); inet_pton(AF_INET6, ip, &s->sin6_addr); l = sizeof *s; }
    else { struct sockaddr_in *s = (void *)&ss; s->sin_family = fam = AF_INET; s->sin_port = htons(port); inet_pton(AF_INET, ip, &s->sin_addr); l = sizeof *s; }
    int fd = socket(fam, SOCK_STREAM, 0);
    int r = tconnect(fd, (void *)&ss, l);
    printf("tcp %-16s %-5d %s\n", ip, port, r == 0 ? "CONNECTED" : strerror(errno)); close(fd);
}
static void udp(const char *ip, int port) {
    struct sockaddr_in s = {.sin_family = AF_INET, .sin_port = htons(port)}; inet_pton(AF_INET, ip, &s.sin_addr);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int r = sendto(fd, "x", 1, 0, (void *)&s, sizeof s);
    printf("udp %-16s %-5d %s\n", ip, port, r == 1 ? "SENT" : strerror(errno)); close(fd);
}
static void unixs(const char *p) {
    struct sockaddr_un s = {.sun_family = AF_UNIX}; strncpy(s.sun_path, p, sizeof s.sun_path - 1);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    int r = connect(fd, (void *)&s, sizeof s);
    printf("unix %-40s %s\n", p, r == 0 ? "CONNECTED" : strerror(errno)); close(fd);
}
int main(int c, char **v) {
    tcp("127.0.0.1", 18080); tcp("127.0.0.2", 18081); tcp("::1", 18082); tcp("0.0.0.0", 18081);
    tcp(v[1], 18081);                       // this mac's LAN/tailscale address
    tcp("1.1.1.1", 80);               // outside
    udp("1.1.1.1", 53); udp("127.0.0.1", 18083);
    unixs("/var/run/mDNSResponder"); unixs("/var/run/amosproxy.sock"); unixs(v[2]);
    struct addrinfo *ai; int r = getaddrinfo("example.com", "80", 0, &ai);
    printf("getaddrinfo example.com %s\n", r == 0 ? "RESOLVED" : gai_strerror(r));
    return 0;
}

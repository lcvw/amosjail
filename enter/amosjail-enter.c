// amosjail-enter: the code between "root, outside" and "the user's command,
// inside the jail" (PLAN §4, T-02). Spawned by amosjaild as root, fresh.
//
//   amosjail-enter --root DIR --uid N --gid N [--groups N,N,...] --cwd DIR
//                  [--tty] [--tag LABEL --amosproxy SOCKET] [--rlimit NAME=N]...
//                  -- CMD [ARG...]
//
//   fd 0-2  the jail's stdio (with --tty: the pty slave on all three)
//   fd 3    the compiled SBPL profile, read to EOF
//   fd 4    status pipe to the daemon: "asid N", "tag {...}", "error ..."
//           (close-on-exec, so EOF with no error means the exec happened)
//   fd 5    control pipe from the daemon: one byte, 'y' to go on
//   environ exactly the jail's environment
//
// Every step either succeeds or ends the process with an "error" line.
// Order: new audit session, report it, [tag it in amosproxy], wait for the
// daemon, compile, chroot, [take the tty], drop to the caller, rlimits,
// close fds, apply the profile, exec.

#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libproc.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/proc_info.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

typedef struct sandbox_profile sandbox_profile_t;
typedef void *sandbox_params_t;
extern sandbox_params_t sandbox_create_params(void);
extern sandbox_profile_t *sandbox_compile_string(const char *, sandbox_params_t, char **);
extern int sandbox_apply(sandbox_profile_t *);

extern char **environ;

enum { FD_PROFILE = 3, FD_STATUS = 4, FD_CONTROL = 5 };

static void status(const char *fmt, ...) {
    char buf[8192];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf - 1, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof buf - 2) n = sizeof buf - 2;
    buf[n++] = '\n';
    for (int off = 0; off < n;) {
        ssize_t w = write(FD_STATUS, buf + off, n - off);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return;
        off += w;
    }
}

__attribute__((noreturn)) static void fail(const char *step) {
    status("error %s: %s", step, strerror(errno));
    _exit(127);
}

__attribute__((noreturn)) static void failmsg(const char *step, const char *msg) {
    status("error %s: %s", step, msg);
    _exit(127);
}

static long number(const char *s, const char *what) {
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || *end || end == s || v < 0) failmsg(what, "not a number");
    return v;
}

static char *read_all(int fd) {
    size_t cap = 1 << 16, len = 0;
    char *buf = malloc(cap);
    if (!buf) fail("profile");
    for (;;) {
        if (len + 1 >= cap) {
            if (cap >= (16u << 20)) failmsg("profile", "too large");
            cap *= 2;
            if (!(buf = realloc(buf, cap))) fail("profile");
        }
        ssize_t r = read(fd, buf + len, cap - len - 1);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) fail("profile");
        if (r == 0) break;
        len += r;
    }
    buf[len] = 0;
    return buf;
}

static int rlimit_resource(const char *name) {
    static const struct { const char *n; int r; } map[] = {
        {"nproc", RLIMIT_NPROC}, {"nofile", RLIMIT_NOFILE}, {"core", RLIMIT_CORE},
        {"cpu", RLIMIT_CPU}, {"fsize", RLIMIT_FSIZE}, {"data", RLIMIT_DATA},
        {"stack", RLIMIT_STACK}, {"as", RLIMIT_AS},
    };
    for (size_t i = 0; i < sizeof map / sizeof *map; i++)
        if (!strcmp(map[i].n, name)) return map[i].r;
    return -1;
}

// The label is checked by the config loader ([A-Za-z0-9._-]); check again
// here, since it is pasted into JSON.
static int label_ok(const char *s) {
    if (!*s || strlen(s) > 64) return 0;
    for (; *s; s++)
        if (!(('a' <= *s && *s <= 'z') || ('A' <= *s && *s <= 'Z') || ('0' <= *s && *s <= '9') ||
              *s == '.' || *s == '_' || *s == '-'))
            return 0;
    return 1;
}

// Ask amosproxy to tag our (new) audit session. It reads the session from
// our audit token; we pass its reply to the daemon, which checks it.
static void tag(const char *sock_path, const char *label) {
    if (!label_ok(label)) failmsg("tag", "bad label");
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) fail("tag socket");
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    if (strlen(sock_path) >= sizeof sa.sun_path) failmsg("tag", "socket path too long");
    strcpy(sa.sun_path, sock_path);
    if (connect(s, (struct sockaddr *)&sa, sizeof sa)) fail("tag connect");
    char req[160];
    int n = snprintf(req, sizeof req, "{\"op\":\"tag\",\"label\":\"%s\"}\n", label);
    if (write(s, req, n) != n) fail("tag write");
    char reply[4096];
    size_t len = 0;
    while (len < sizeof reply - 1) {
        ssize_t r = read(s, reply + len, sizeof reply - 1 - len);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        len += r;
        if (memchr(reply, '\n', len)) break;
    }
    close(s);
    reply[len] = 0;
    char *nl = strchr(reply, '\n');
    if (!nl) failmsg("tag", "no reply from amosproxy");
    *nl = 0;
    status("tag %s", reply);
}

static void close_other_fds(void) {
    // Everything but stdio and the status pipe (close-on-exec).
    int n = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, NULL, 0);
    if (n <= 0) fail("list fds");
    struct proc_fdinfo *fds = malloc(n);
    if (!fds) fail("list fds");
    n = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds, n);
    if (n <= 0) fail("list fds");
    for (int i = 0; i < n / (int)sizeof *fds; i++) {
        int fd = fds[i].proc_fd;
        if (fd > 2 && fd != FD_STATUS) close(fd);
    }
    free(fds);
}

int main(int argc, char **argv) {
    const char *root = NULL, *cwd = NULL, *label = NULL, *proxy_sock = NULL, *groups_arg = "";
    long uid = -1, gid = -1;
    int want_tty = 0;
    struct { int res; rlim_t v; } limits[16];
    int nlimits = 0;

    if (fcntl(FD_STATUS, F_SETFD, FD_CLOEXEC)) _exit(127);  // no status pipe: nobody to tell

    int i = 1;
    for (; i < argc; i++) {
        const char *a = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(a, "--")) { i++; break; }
        if (!strcmp(a, "--tty")) { want_tty = 1; continue; }
        if (!v) failmsg("args", a);
        i++;
        if (!strcmp(a, "--root")) root = v;
        else if (!strcmp(a, "--cwd")) cwd = v;
        else if (!strcmp(a, "--uid")) uid = number(v, "--uid");
        else if (!strcmp(a, "--gid")) gid = number(v, "--gid");
        else if (!strcmp(a, "--groups")) groups_arg = v;
        else if (!strcmp(a, "--tag")) label = v;
        else if (!strcmp(a, "--amosproxy")) proxy_sock = v;
        else if (!strcmp(a, "--rlimit")) {
            const char *eq = strchr(v, '=');
            char name[16];
            if (!eq || eq - v >= (long)sizeof name || nlimits == 16) failmsg("--rlimit", v);
            memcpy(name, v, eq - v);
            name[eq - v] = 0;
            if ((limits[nlimits].res = rlimit_resource(name)) < 0) failmsg("--rlimit", v);
            limits[nlimits++].v = number(eq + 1, "--rlimit");
        } else failmsg("args", a);
    }
    if (!root || !cwd || uid < 0 || gid < 0 || i >= argc) failmsg("args", "missing --root/--cwd/--uid/--gid or command");
    if (uid == 0) failmsg("args", "refusing to run a jail as root");
    if (!!label != !!proxy_sock) failmsg("args", "--tag and --amosproxy go together");
    char **cmd = argv + i;

    gid_t groups[NGROUPS_MAX];
    int ngroups = 0;
    groups[ngroups++] = gid;
    for (const char *p = groups_arg; *p;) {
        char *end;
        long g = strtol(p, &end, 10);
        if (end == p || g < 0 || ngroups == NGROUPS_MAX) failmsg("--groups", groups_arg);
        if (g != gid) groups[ngroups++] = g;
        p = *end == ',' ? end + 1 : end;
        if (*end && *end != ',') failmsg("--groups", groups_arg);
    }

    char *profile = read_all(FD_PROFILE);
    close(FD_PROFILE);

    // 1. A fresh audit session: the jail's identity for amosproxy and for
    //    teardown. Only root can do this; nothing in the jail can undo it.
    auditinfo_addr_t ai;
    if (getaudit_addr(&ai, sizeof ai)) fail("getaudit_addr");
    ai.ai_asid = AU_ASSIGN_ASID;
    if (setaudit_addr(&ai, sizeof ai)) fail("setaudit_addr");
    if (getaudit_addr(&ai, sizeof ai)) fail("getaudit_addr");
    status("asid %d", ai.ai_asid);

    // 2. Tag it, while still root and in the new session.
    if (label) tag(proxy_sock, label);

    // 3. The daemon records the session (and checks the tag) before any
    //    jailed code can exist.
    char go = 0;
    ssize_t r;
    while ((r = read(FD_CONTROL, &go, 1)) < 0 && errno == EINTR) {}
    if (r != 1 || go != 'y') failmsg("handshake", "daemon said no");
    close(FD_CONTROL);

    // 4. Compile while the host filesystem is visible (D-5).
    char *err = NULL;
    sandbox_profile_t *sp = sandbox_compile_string(profile, sandbox_create_params(), &err);
    if (!sp) failmsg("compile", err ? err : "unknown error");

    // 5. Into the jail.
    if (chroot(root)) fail("chroot");
    if (chdir("/")) fail("chdir /");

    // 6. The pty becomes our controlling terminal, in a session of our own.
    if (want_tty) {
        if (setsid() < 0) fail("setsid");
        if (ioctl(0, TIOCSCTTY, 0)) fail("TIOCSCTTY");
    }

    // 7. Become the caller: every gid explicitly (chroot -u leaves wheel).
    if (setgroups(ngroups, groups)) fail("setgroups");
    if (setgid(gid) || setegid(gid)) fail("setgid");
    if (setuid(uid) || seteuid(uid)) fail("setuid");
    if (setuid(0) == 0 || seteuid(0) == 0) failmsg("setuid", "regained root");
    if (getuid() != (uid_t)uid || geteuid() != (uid_t)uid || getgid() != (gid_t)gid || getegid() != (gid_t)gid)
        failmsg("setuid", "ids did not change");
    if (chdir(cwd)) fail("chdir");

    for (int k = 0; k < nlimits; k++) {
        struct rlimit rl = {limits[k].v, limits[k].v};
        if (setrlimit(limits[k].res, &rl)) fail("setrlimit");
    }

    // 8. Nothing from outside but stdio (E10), then the profile, then exec.
    //    The first sandboxed instruction is the target's.
    close_other_fds();
    if (sandbox_apply(sp)) fail("sandbox_apply");
    execvp(cmd[0], cmd);
    status("error exec %s: %s", cmd[0], strerror(errno));
    _exit(127);
}

// enter PROFILE ROOT UID GID CMD...: ROOT "-" for no chroot.
// enter PROFILE UID GID CMD...: compile PROFILE (with param JAIL_ID) as the caller,
// drop to UID/GID with no supplementary groups, close fds >= 3, apply, exec.
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct sandbox_profile sandbox_profile_t;
typedef void *sandbox_params_t;
extern sandbox_params_t sandbox_create_params(void);
extern int sandbox_set_param(sandbox_params_t, const char *, const char *);
extern sandbox_profile_t *sandbox_compile_string(const char *, sandbox_params_t, char **);
extern int sandbox_apply(sandbox_profile_t *);

static void die(const char *m) { fprintf(stderr, "enter: %s: %s\n", m, strerror(errno)); exit(126); }

int main(int argc, char **argv) {
    if (argc < 6) { fprintf(stderr, "usage: enter PROFILE ROOT UID GID CMD...\n"); return 2; }
    const char *profile = argv[1], *root = argv[2]; argv++;
    FILE *f = fopen(profile, "r"); if (!f) die("open profile");
    static char prof[1 << 20]; size_t n = fread(prof, 1, sizeof prof - 1, f); prof[n] = 0; fclose(f);
    sandbox_params_t p = sandbox_create_params();
    sandbox_set_param(p, "JAIL_ID", "j-test");
    sandbox_set_param(p, "JAIL", getenv("JAIL") ? getenv("JAIL") : "/nonexistent");
    char *err = NULL;
    sandbox_profile_t *sp = sandbox_compile_string(prof, p, &err);
    if (!sp) { fprintf(stderr, "enter: compile: %s\n", err ? err : "?"); return 126; }
    if (strcmp(root, "-")) { if (chroot(root) || chdir("/")) die("chroot"); }
    uid_t uid = atoi(argv[2]); gid_t gid = atoi(argv[3]);
    if (getuid() == 0) {
        if (setgroups(1, &gid)) die("setgroups");
        if (setgid(gid)) die("setgid");
        if (setuid(uid)) die("setuid");
        if (setuid(0) == 0) { fprintf(stderr, "enter: regained root\n"); return 126; }
    }
    for (int fd = 3; fd < 1024; fd++) close(fd);
    if (sandbox_apply(sp)) die("sandbox_apply");
    execv(argv[4], argv + 4);
    die("exec");
}

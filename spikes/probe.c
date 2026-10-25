// probe <pid>: try every way of reaching another process; print one line per attempt.
#include <errno.h>
#include <libproc.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <unistd.h>

extern kern_return_t task_read_for_pid(mach_port_t, int, mach_port_t *);
extern kern_return_t task_inspect_for_pid(mach_port_t, int, mach_port_t *);
extern int pid_suspend(int);
extern int pid_resume(int);

static void res(const char *what, int ok, const char *detail) {
    printf("%-22s %s %s\n", what, ok ? "ALLOWED" : "denied ", detail);
}
static void rc(const char *what, int r) {
    char b[64]; snprintf(b, sizeof b, "(r=%d errno=%s)", r, r < 0 ? strerror(errno) : "-");
    res(what, r >= 0, b);
}
static void kr(const char *what, kern_return_t k) {
    char b[64]; snprintf(b, sizeof b, "(kr=%d %s)", k, mach_error_string(k));
    res(what, k == KERN_SUCCESS, b);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: probe pid [kill]\n"); return 2; }
    pid_t pid = atoi(argv[1]);
    mach_port_t t;
    errno = 0; rc("kill(0)", kill(pid, 0));
    errno = 0; rc("kill(SIGCONT)", kill(pid, SIGCONT));
    errno = 0; rc("pid_suspend", pid_suspend(pid)); pid_resume(pid);
    kr("task_for_pid", task_for_pid(mach_task_self(), pid, &t));
    kr("task_read_for_pid", task_read_for_pid(mach_task_self(), pid, &t));
    kr("task_inspect_for_pid", task_inspect_for_pid(mach_task_self(), pid, &t));
    kr("task_name_for_pid", task_name_for_pid(mach_task_self(), pid, &t));
    struct proc_bsdinfo bi;
    int n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bi, sizeof bi);
    res("proc_pidinfo(BSD)", n == sizeof bi, n == sizeof bi ? bi.pbi_comm : strerror(errno));
    char path[PROC_PIDPATHINFO_MAXSIZE];
    n = proc_pidpath(pid, path, sizeof path);
    res("proc_pidpath", n > 0, n > 0 ? path : strerror(errno));
    int mib[3] = {CTL_KERN, KERN_PROCARGS2, pid}; char args[4096]; size_t sz = sizeof args;
    n = sysctl(mib, 3, args, &sz, NULL, 0);
    res("sysctl(PROCARGS2)", n == 0, n == 0 ? args + sizeof(int) : strerror(errno));
    int pids[4096]; n = proc_listallpids(pids, sizeof pids);
    char cnt[32]; snprintf(cnt, sizeof cnt, "(%d pids)", n);
    res("proc_listallpids", n > 0, cnt);
    // ptrace last: a successful attach stops the target.
    errno = 0; int r = ptrace(PT_ATTACHEXC, pid, 0, 0); rc("ptrace(PT_ATTACHEXC)", r);
    if (r == 0) { ptrace(PT_DETACH, pid, (caddr_t)1, 0); }
    if (argc > 2) { errno = 0; rc("kill(SIGKILL)", kill(pid, SIGKILL)); }
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/sysctl.h>
int main(int c, char **v) {
    int pid = atoi(v[1]);
    int mib[3] = {CTL_KERN, KERN_PROCARGS2, pid}; char a[8192]; size_t sz = sizeof a;
    if (sysctl(mib, 3, a, &sz, 0, 0)) { printf("PROCARGS2 denied: %s\n", strerror(errno)); }
    else {  // print the environment too
        int argc = *(int *)a; char *p = a + sizeof(int); p += strlen(p) + 1;
        while (p < a + sz && !*p) p++;
        for (int i = 0; i < argc && p < a + sz; i++) p += strlen(p) + 1;
        printf("PROCARGS2 ALLOWED argc=%d first env: %s\n", argc, p < a + sz ? p : "-");
    }
    int mib2[3] = {CTL_KERN, KERN_PROCARGS, pid}; sz = sizeof a;
    printf("PROCARGS  %s\n", sysctl(mib2, 3, a, &sz, 0, 0) ? strerror(errno) : "ALLOWED");
    int mib3[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid}; struct kinfo_proc kp; sz = sizeof kp;
    printf("KERN_PROC %s\n", sysctl(mib3, 4, &kp, &sz, 0, 0) || sz == 0 ? "denied" : kp.kp_proc.p_comm);
    int mib4[3] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL}; sz = 0;
    printf("PROC_ALL  %s\n", sysctl(mib4, 3, 0, &sz, 0, 0) ? strerror(errno) : "ALLOWED");
    char h[256]; sz = sizeof h;
    printf("kern.hostname %s\n", sysctlbyname("kern.hostname", h, &sz, 0, 0) ? strerror(errno) : h);
    return 0;
}

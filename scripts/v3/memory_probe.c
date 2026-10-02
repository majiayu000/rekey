/* macOS V2 experiment: obtain and immediately release a task port; never read it.
 * Build: xcrun clang -std=c11 -Wall -Wextra -Werror memory_probe.c -o memory_probe
 * Usage: memory_probe --pid PID | --target
 * Exit: 0 = acquired, 1 = denied, 2 = invalid/inconclusive/error.
 * A denied result does not identify its cause. A cross-process positive control
 * is required before attributing a difference to hardened runtime. Self access
 * only checks that this utility can obtain a task port.
 */
#include <errno.h>
#include <limits.h>
#include <libproc.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc.h>
#include <unistd.h>

static int report(const char *status, pid_t pid, const struct proc_bsdinfo *info,
                  bool called, kern_return_t kr, bool acquired,
                  bool released, kern_return_t release_kr, const char *phase,
                  int error, int exit_code)
{
    printf("{\"status\":\"%s\",\"caller_pid\":%d,\"caller_uid\":%u,"
           "\"caller_euid\":%u,\"target_pid\":", status, getpid(),
           (unsigned)getuid(), (unsigned)geteuid());
    if (pid > 0) printf("%d", pid); else printf("null");
    printf(",\"target_uid\":");
    if (info) printf("%u", (unsigned)info->pbi_ruid); else printf("null");
    printf(",\"target_euid\":");
    if (info) printf("%u", (unsigned)info->pbi_uid); else printf("null");
    printf(",\"kern_return\":");
    if (called) printf("%d", kr); else printf("null");
    printf(",\"task_port_acquired\":%s,\"deallocate_return\":",
           acquired ? "true" : "false");
    if (released) printf("%d", release_kr); else printf("null");
    printf(",\"phase\":\"%s\",\"errno\":%d}\n", phase, error);
    return fflush(stdout) == EOF ? 2 : exit_code;
}

static int snapshot(pid_t pid, struct proc_bsdinfo *info)
{
    errno = 0;
    int size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, info, sizeof(*info));
    if (size == sizeof(*info)) return 0;
    return errno ? errno : EIO;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--target") == 0) {
        volatile char canary[] = "rekey-v3-public-synthetic-canary";
        printf("{\"status\":\"target_ready\",\"pid\":%d,\"uid\":%u,"
               "\"euid\":%u,\"synthetic\":true}\n", getpid(),
               (unsigned)getuid(), (unsigned)geteuid());
        if (fflush(stdout) == EOF) return 2;
        for (;;) {
            (void)canary[0];
            pause();
        }
    }

    if (argc != 3 || strcmp(argv[1], "--pid") != 0) {
        fprintf(stderr, "Usage: %s --pid PID | --target\n", argv[0]);
        return report("invalid_arguments", 0, NULL, false, 0, false, false, 0,
                      "arguments", 0, 2);
    }
    const char *arg = argv[2];
    bool digits = *arg != '\0';
    for (const char *p = arg; *p; ++p) {
        if (*p < '0' || *p > '9') digits = false;
    }
    errno = 0;
    unsigned long value = digits ? strtoul(arg, NULL, 10) : 0;
    if (!digits || errno || value == 0 || value > INT_MAX) {
        return report("invalid_pid", 0, NULL, false, 0, false, false, 0,
                      "arguments", errno, 2);
    }
    pid_t pid = (pid_t)value;
    struct proc_bsdinfo before = {0}, after = {0};
    int error = snapshot(pid, &before);
    if (error) {
        return report(error == ESRCH ? "target_missing" : "unexpected_error",
                      pid, NULL, false, 0, false, false, 0, "before", error, 2);
    }
    if (before.pbi_status == SZOMB) {
        return report("target_exited", pid, &before, false, 0, false, false, 0,
                      "before", 0, 2);
    }

    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    bool acquired = kr == KERN_SUCCESS && MACH_PORT_VALID(task);
    bool released = MACH_PORT_VALID(task);
    kern_return_t release_kr = released
        ? mach_port_deallocate(mach_task_self(), task) : KERN_SUCCESS;
    error = snapshot(pid, &after);
    const char *status = "unexpected_error";
    const char *phase = "task_for_pid";
    int exit_code = 2;
    if (released && release_kr != KERN_SUCCESS) {
        phase = "deallocate";
    } else if (error) {
        status = error == ESRCH ? "target_vanished" : "unexpected_error";
        phase = "after";
    } else if (before.pbi_start_tvsec != after.pbi_start_tvsec ||
               before.pbi_start_tvusec != after.pbi_start_tvusec ||
               before.pbi_uid != after.pbi_uid ||
               before.pbi_ruid != after.pbi_ruid) {
        status = "target_changed";
        phase = "after";
    } else if (after.pbi_status == SZOMB) {
        status = "target_exited";
        phase = "after";
    } else if (acquired) {
        status = "acquired";
        exit_code = 0;
    } else if (!released && (kr == KERN_FAILURE ||
                            kr == KERN_PROTECTION_FAILURE || kr == KERN_NO_ACCESS)) {
        /* These return codes can have several causes; do not attribute policy. */
        status = "denied";
        exit_code = 1;
    }
    return report(status, pid, &before, true, kr, acquired, released, release_kr,
                  phase, error, exit_code);
}

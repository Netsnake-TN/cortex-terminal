/*
 * cortex-redirect.c — seccomp supervisor for raw "/home" syscalls.
 *
 * kilo is a STATIC Bun ELF → ignores LD_PRELOAD → libcortex-hook never loads
 * → Bun's RAW syscalls hit Android's real (absent) /home → "realpath '/home'
 * ENOENT". seccomp user-notif is the only way to catch a static binary's raw
 * syscalls (pattern proven by codex-dns-redirect).
 *
 * PARENT supervisor (NOT filtered) polls notifications from the CHILD that
 * installed the filter and exec'd the target. Under "/home":
 *   - openat            → open $CORTEX_ROOT/home… in parent, ADDFD into child
 *   - statx/newfstatat  → stat $CORTEX_ROOT/home… in parent, write struct to child
 * Other paths: SECCOMP_USER_NOTIF_FLAG_CONTINUE (original syscall runs).
 *
 * NOTE (accept/accept4 intentionally NOT handled): the guest's app seccomp allows
 * accept4() natively and only SIGSYS-blocks legacy accept(); the guest glibc hook
 * already shims accept()→accept4() for dynamic tools, and Bun's libuv calls
 * accept4() directly. So no wrapped tool needs accept translation here — and a
 * client-server daemon (tmux) can't be supervised by this process anyway (it
 * outlives its launching client). Such daemons are dynamic glibc and are left to
 * the hook, never wrapped (see BootstrapManager.ensureRawSyscallRedirects).
 *
 * Build (GLIBC — REQUIRED so the guest's glibc LD_PRELOAD hook loads into this
 * entry point; a bionic build would be routed through the guest ld.so and fail.
 * See BUILD-GUIDE.md §Glibc / build-glibc.sh):
 *   CPATH=$PREFIX/glibc/include clang --target=aarch64-linux-gnu -nostdlib \
 *     $PREFIX/glibc/lib/Scrt1.o -Wl,--library-path=$PREFIX/glibc/lib \
 *     -lc -lgcc_s -o cortex-redirect cortex-redirect.c
 *
 * Deploy: copy this binary as the tool's name (e.g. "kilo") with the real ELF
 * kept as a "<tool>.real" sibling — it self-locates the target. Or invoke the
 * dispatcher explicitly: cortex-redirect <cmd> [args…].
 * Env: CORTEX_ROOT (default org.cortex root), CORTEX_DEBUG=1, CORTEX_ERRSIGN=+
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/limits.h>
#include <linux/seccomp.h>
#include <linux/stat.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef __NR_newfstatat
#define __NR_newfstatat 79      /* aarch64 generic syscall number */
#endif
#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434     /* aarch64 generic syscall number */
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438    /* aarch64 generic syscall number */
#endif

static char g_root[PATH_MAX];
static int  g_neg_errno = 1;    /* resp.error = -errno ; override: CORTEX_ERRSIGN=+ */
static int  g_child_status = 0;
static int  g_debug = 0;

static void logmsg(const char *fmt, ...) {
    if (!g_debug) return;
    va_list ap; va_start(ap, fmt);
    fprintf(stderr, "[cortex-redirect] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static void build_paths(void) {
    const char *r = getenv("CORTEX_ROOT");
    if (!r || !*r) r = "/data/user/0/org.cortex.terminal/files/cortex";
    snprintf(g_root, sizeof(g_root), "%s", r);
    size_t L = strlen(g_root);
    while (L > 1 && g_root[L - 1] == '/') g_root[--L] = '\0';
    const char *s = getenv("CORTEX_ERRSIGN");
    if (s && s[0] == '+') g_neg_errno = 0;
    if (getenv("CORTEX_DEBUG")) g_debug = 1;
}

/* "/home" or "/home/..." → "$ROOT/home..." (static buf). Else NULL. */
static const char *redirect_path(const char *path) {
    if (!path || path[0] != '/') return NULL;
    if (strcmp(path, "/home") != 0 && strncmp(path, "/home/", 6) != 0)
        return NULL;
    static char buf[PATH_MAX];
    snprintf(buf, sizeof(buf), "%s%s", g_root, path);
    return buf;
}

static ssize_t read_proc_string(pid_t pid, unsigned long addr, char *buf, size_t bufsz) {
    char proc_mem[64];
    snprintf(proc_mem, sizeof(proc_mem), "/proc/%d/mem", (int)pid);
    int fd = open(proc_mem, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = pread(fd, buf, bufsz - 1, (off_t)addr);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    char *nul = memchr(buf, '\0', (size_t)n);
    return nul ? (nul - buf + 1) : -1;
}

static ssize_t write_proc_memory(pid_t pid, unsigned long addr, const void *src, size_t len) {
    char proc_mem[64];
    snprintf(proc_mem, sizeof(proc_mem), "/proc/%d/mem", (int)pid);
    int fd = open(proc_mem, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = pwrite(fd, src, len, (off_t)addr);
    close(fd);
    return n;
}

static int send_fd(int sock, int fd) {
    char buf[1] = { 'F' };
    struct iovec iov = { .iov_base = buf, .iov_len = 1 };
    union { char buf[CMSG_SPACE(sizeof(int))]; struct cmsghdr align; } cb;
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
                          .msg_control = cb.buf, .msg_controllen = sizeof(cb.buf) };
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof(int));
    return (sendmsg(sock, &msg, 0) >= 0) ? 0 : -1;
}

static int recv_fd(int sock) {
    char buf[1];
    struct iovec iov = { .iov_base = buf, .iov_len = 1 };
    union { char buf[CMSG_SPACE(sizeof(int))]; struct cmsghdr align; } cb;
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
                          .msg_control = cb.buf, .msg_controllen = sizeof(cb.buf) };
    if (recvmsg(sock, &msg, 0) < 0) return -1;
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    if (!c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS ||
        c->cmsg_len != CMSG_LEN(sizeof(int))) return -1;
    int fd; memcpy(&fd, CMSG_DATA(c), sizeof(int));
    return fd;
}

/* Open the REAL target for a /home path; -1 if it can't be opened.
 * O_PATH is stripped: an O_PATH srcfd makes SECCOMP_IOCTL_NOTIF_ADDFD fail
 * with EBADF (verified locally). A regular fd serves the child's
 * fstatat/readlink/relative-open needs identically. */
static int try_redirect_open(const char *path, int flags) {
    const char *real = redirect_path(path);
    if (!real) return -1;
    int f = flags & ~O_PATH;
    int fd = open(real, f | O_CLOEXEC);
    logmsg("openat '%s' -> '%s' flags=0x%x fd=%d (%s)", path, real, f, fd,
           fd < 0 ? strerror(errno) : "ok");
    return fd;
}

/* Notify on aarch64 openat / statx / newfstatat; else allow. */
static int install_seccomp_filter(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat,     0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_statx,      0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_newfstatat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                        SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
}
static void respond(int notif_fd, struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    resp->id = req->id;
    if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0 && errno != ENOENT)
        logmsg("NOTIF_SEND failed: %s", strerror(errno));
}

static int handle_notification(int notif_fd) {
    struct seccomp_notif req;
    struct seccomp_notif_resp resp;
    memset(&req, 0, sizeof(req));
    if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
        if (errno == ENOENT || errno == EINTR) return 0;
        return -1;
    }

    memset(&resp, 0, sizeof(resp));
    resp.id = req.id;
    resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;   /* default: run original */

    pid_t pid = req.pid;

    unsigned long path_addr = req.data.args[1];
    char path_buf[PATH_MAX];

    if (path_addr == 0 || read_proc_string(pid, path_addr, path_buf, sizeof(path_buf)) <= 0)
        goto send;
    if (!redirect_path(path_buf))
        goto send;                                     /* not a /home path */

    if (req.data.nr == __NR_openat) {
        int flags = (int)req.data.args[2];
        int redir_fd = try_redirect_open(path_buf, flags);
        if (redir_fd < 0) goto send;                   /* absent → let original run */
        if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &req.id) < 0) {
            close(redir_fd);
            return 0;
        }
        struct seccomp_notif_addfd addfd = {
            .id = req.id,
            .flags = SECCOMP_ADDFD_FLAG_SEND,
            .srcfd = (unsigned int)redir_fd,
            .newfd = 0,
            .newfd_flags = 0,
        };
        int ret = ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
        int saved = errno;
        close(redir_fd);
        logmsg("ADDFD srcfd=%d ret=%d err=%d(%s)", redir_fd, ret,
               ret < 0 ? saved : 0, ret < 0 ? strerror(saved) : "ok");
        if (ret >= 0) return 0;
        if (saved == ENOENT) return 0;
        goto send;                                     /* ADDFD failed → continue */
    }

    if (req.data.nr == __NR_statx) {
        int flags = (int)req.data.args[2];
        unsigned mask = (unsigned)req.data.args[3];
        unsigned long buf_addr = req.data.args[4];
        const char *real = redirect_path(path_buf);
        struct statx sx;
        memset(&sx, 0, sizeof(sx));
        int rc = syscall(SYS_statx, AT_FDCWD, real, flags, mask, &sx);
        resp.flags = 0;                                /* we supply the result */
        if (rc == 0) {
            if (write_proc_memory(pid, buf_addr, &sx, sizeof(sx)) != (ssize_t)sizeof(sx))
                resp.error = g_neg_errno ? -EFAULT : EFAULT;
            else
                resp.error = 0, resp.val = 0;
        } else {
            resp.error = g_neg_errno ? -errno : errno;
        }
        logmsg("statx '%s' -> '%s' rc=%d err=%d", path_buf, real, rc, resp.error);
        respond(notif_fd, &req, &resp);
        return 0;
    }

    if (req.data.nr == __NR_newfstatat) {
        int flags = (int)req.data.args[3];
        unsigned long buf_addr = req.data.args[2];
        const char *real = redirect_path(path_buf);
        struct stat st;
        memset(&st, 0, sizeof(st));
        int rc = fstatat(AT_FDCWD, real, &st, flags);
        resp.flags = 0;
        if (rc == 0) {
            if (write_proc_memory(pid, buf_addr, &st, sizeof(st)) != (ssize_t)sizeof(st))
                resp.error = g_neg_errno ? -EFAULT : EFAULT;
            else
                resp.error = 0, resp.val = 0;
        } else {
            resp.error = g_neg_errno ? -errno : errno;
        }
        logmsg("newfstatat '%s' -> '%s' rc=%d err=%d", path_buf, real, rc, resp.error);
        respond(notif_fd, &req, &resp);
        return 0;
    }

send:
    respond(notif_fd, &req, &resp);
    return 0;
}

int main(int argc, char *argv[]) {
    build_paths();

    /* Resolve the target:
     *   invoked as "cortex-redirect" → argv[1] is the command
     *   invoked as a wrapped tool (e.g. a copy named "kilo") → sibling "<tool>.real" */
    const char *base = strrchr(argv[0], '/');
    base = base ? base + 1 : argv[0];
    int as_dispatch = (strcmp(base, "cortex-redirect") == 0);
    if (as_dispatch && argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args…]\n", argv[0]);
        return 1;
    }

    char target_buf[PATH_MAX];
    const char *target;
    int arg_start;
    if (as_dispatch) {
        target = argv[1];
        arg_start = 2;
    } else {
        const char *slash = strrchr(argv[0], '/');
        if (slash) {
            snprintf(target_buf, sizeof(target_buf), "%.*s%s.real",
                     (int)(slash - argv[0] + 1), argv[0], base);
        } else {
            char self[PATH_MAX];
            ssize_t rn = readlink("/proc/self/exe", self, sizeof(self) - 1);
            if (rn > 0) {
                self[rn] = '\0';
                char *s2 = strrchr(self, '/');
                if (s2) *s2 = '\0';
                snprintf(target_buf, sizeof(target_buf), "%s/%s.real", self, base);
            } else {
                snprintf(target_buf, sizeof(target_buf), "%s.real", base);
            }
        }
        target = target_buf;
        arg_start = 1;
    }
    logmsg("target=%s as_dispatch=%d", target, as_dispatch);

    int sock_fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds) < 0) { perror("socketpair"); return 1; }

    pid_t child = fork();
    if (child < 0) { perror("fork"); return 1; }

    if (child == 0) {                                  /* CHILD: filter + exec */
        close(sock_fds[0]);
        /* Raw syscall, NOT prctl(): the guest cortex-hook INTERPOSES
         * prctl(PR_SET_NO_NEW_PRIVS) and fakes success (returns 0 without
         * setting the flag). Without no_new_privs the kernel then rejects the
         * seccomp install below with EACCES. syscall() bypasses the hook. */
        if (syscall(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) < 0) {
            perror("prctl(NO_NEW_PRIVS)");
            _exit(1);
        }
        int notif_fd = install_seccomp_filter();
        if (notif_fd < 0) { perror("seccomp install"); _exit(1); }
        if (send_fd(sock_fds[1], notif_fd) < 0) { perror("send_fd"); _exit(1); }
        char ack;
        if (read(sock_fds[1], &ack, 1) <= 0) _exit(1);
        close(notif_fd);
        close(sock_fds[1]);
        /* child argv = [target, argv[arg_start … argc-1]] */
        char **cargv = (char **)calloc((size_t)(argc - arg_start + 2), sizeof(char *));
        int n = 0;
        cargv[n++] = (char *)target;
        for (int i = arg_start; i < argc; i++) cargv[n++] = argv[i];
        cargv[n] = NULL;
        execvp(target, cargv);
        perror(target);
        _exit(127);
    }

    /* PARENT: unfiltered supervisor */
    close(sock_fds[1]);
    int notif_fd = recv_fd(sock_fds[0]);
    if (notif_fd < 0) {
        fprintf(stderr, "failed to receive notif fd\n");
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 1;
    }
    char ack = 'A';
    if (write(sock_fds[0], &ack, 1) < 0) {}
    close(sock_fds[0]);

    for (;;) {
        pid_t w = waitpid(child, &g_child_status, WNOHANG);
        if (w > 0) break;
        if (w < 0 && errno != EINTR) break;
        struct pollfd pfd = { .fd = notif_fd, .events = POLLIN };
        int ret = poll(&pfd, 1, 100);
        if (ret < 0) { if (errno == EINTR) continue; break; }
        if (ret > 0) {
            if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) break;
            if (pfd.revents & POLLIN)
                if (handle_notification(notif_fd) < 0) break;
        }
    }
    close(notif_fd);
    waitpid(child, &g_child_status, 0);
    if (WIFEXITED(g_child_status)) return WEXITSTATUS(g_child_status);
    if (WIFSIGNALED(g_child_status)) {
        signal(WTERMSIG(g_child_status), SIG_DFL);
        raise(WTERMSIG(g_child_status));
    }
    return 1;
}
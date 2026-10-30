// Part of libcortex-hook.so, included by cortex-hook.c (one translation unit, so the
// parts share their static functions and are built with the same command as before).
//
// The SIGSYS handler for system calls Android's seccomp filter blocks, and the signal hooks that
// keep programs from replacing or blocking it.

#ifndef CORTEX_HOST_TEST

#include "hook-common.h"

#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

static int (*get_real_sigaction(void))(int, const struct sigaction *, struct sigaction *);

// Intercept SECCOMP blocked syscalls (SIGSYS), answer -ENOSYS so glibc/raw
// syscalls fall back, and advance PC past the trapped svc #0. Without the
// advance the same instruction re-executes on return and re-traps forever —
// which is what kills dynamic Bun/Go tool spawns.
// Forward-only check: read only the mapped instruction at PC (never PC-4,
// which can cross a page boundary and fault inside the handler), and it's a
// no-op if PC is not the trapped `svc #0`.
static void cortex_sigsys_handler(int sig, siginfo_t *info, void *ctx) {
    (void)sig;
    if (!ctx) return;
    ucontext_t *uctx = (ucontext_t *)ctx;
    if (info && info->si_code != SYS_SECCOMP) return;
#if defined(__aarch64__)
    uctx->uc_mcontext.regs[0] = (uint64_t)-ENOSYS;
    uint32_t at = 0;
    memcpy(&at, (const void *)uctx->uc_mcontext.pc, sizeof at);
    if (at == 0xd4000001U) uctx->uc_mcontext.pc += 4;
#elif defined(__arm__)
    uctx->uc_mcontext.arm_r0 = (unsigned long)-ENOSYS;
#elif defined(__x86_64__) && defined(REG_RAX)
    uctx->uc_mcontext.gregs[REG_RAX] = (greg_t)-ENOSYS;
#elif defined(__i386__) && defined(REG_EAX)
    uctx->uc_mcontext.gregs[REG_EAX] = (greg_t)-ENOSYS;
#endif
}

static int (*get_real_sigaction(void))(int, const struct sigaction *, struct sigaction *) {
    static int (*real_sigaction)(int, const struct sigaction *, struct sigaction *) = NULL;
    if (!real_sigaction) {
        real_sigaction = (int (*)(int, const struct sigaction *, struct sigaction *))dlsym(RTLD_NEXT, "sigaction");
        if (!real_sigaction) {
            real_sigaction = (int (*)(int, const struct sigaction *, struct sigaction *))dlsym(RTLD_DEFAULT, "sigaction");
        }
    }
    return real_sigaction;
}

__attribute__((constructor(101))) static void install_sigsys_handler(void) {
    int (*real_sig)(int, const struct sigaction *, struct sigaction *) = get_real_sigaction();
    if (!real_sig) return;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = cortex_sigsys_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    real_sig(SIGSYS, &sa, NULL);
}

int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
    int (*real_sig)(int, const struct sigaction *, struct sigaction *) = get_real_sigaction();
    if (!real_sig) return -1;

    if (signum == SIGSYS) {
        if (act && act->sa_sigaction == cortex_sigsys_handler) {
            return real_sig(signum, act, oldact);
        }
        if (oldact) {
            memset(oldact, 0, sizeof(*oldact));
            oldact->sa_sigaction = cortex_sigsys_handler;
            oldact->sa_flags = SA_SIGINFO | SA_RESTART;
        }
        return 0;
    }
    return real_sig(signum, act, oldact);
}

int rt_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact, size_t sigsetsize) {
    static int (*orig_rt_sigaction)(int, const struct sigaction *, struct sigaction *, size_t) = NULL;
    if (!orig_rt_sigaction) orig_rt_sigaction = (int (*)(int, const struct sigaction *, struct sigaction *, size_t))dlsym(RTLD_NEXT, "rt_sigaction");

    if (signum == SIGSYS) {
        if (act && act->sa_sigaction == cortex_sigsys_handler) {
            return orig_rt_sigaction ? orig_rt_sigaction(signum, act, oldact, sigsetsize) : 0;
        }
        if (oldact) {
            memset(oldact, 0, sizeof(*oldact));
            oldact->sa_sigaction = cortex_sigsys_handler;
            oldact->sa_flags = SA_SIGINFO | SA_RESTART;
        }
        return 0;
    }
    return orig_rt_sigaction ? orig_rt_sigaction(signum, act, oldact, sigsetsize) : -1;
}

int __libc_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
    return sigaction(signum, act, oldact);
}

typedef void (*sighandler_t)(int);
sighandler_t signal(int signum, sighandler_t handler) {
    static sighandler_t (*orig_signal)(int, sighandler_t) = NULL;
    if (!orig_signal) orig_signal = (sighandler_t (*)(int, sighandler_t))dlsym(RTLD_NEXT, "signal");
    if (signum == SIGSYS) {
        return (sighandler_t)cortex_sigsys_handler;
    }
    return orig_signal ? orig_signal(signum, handler) : NULL;
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
    static int (*orig_sigprocmask)(int, const sigset_t *, sigset_t *) = NULL;
    if (!orig_sigprocmask) orig_sigprocmask = (int (*)(int, const sigset_t *, sigset_t *))dlsym(RTLD_NEXT, "sigprocmask");
    if (set && (how == SIG_BLOCK || how == SIG_SETMASK)) {
        sigset_t mod_set = *set;
        sigdelset(&mod_set, SIGSYS);
        return orig_sigprocmask ? orig_sigprocmask(how, &mod_set, oldset) : 0;
    }
    return orig_sigprocmask ? orig_sigprocmask(how, set, oldset) : 0;
}

int pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset) {
    static int (*orig_pthread_sigmask)(int, const sigset_t *, sigset_t *) = NULL;
    if (!orig_pthread_sigmask) orig_pthread_sigmask = (int (*)(int, const sigset_t *, sigset_t *))dlsym(RTLD_NEXT, "pthread_sigmask");
    if (set && (how == SIG_BLOCK || how == SIG_SETMASK)) {
        sigset_t mod_set = *set;
        sigdelset(&mod_set, SIGSYS);
        return orig_pthread_sigmask ? orig_pthread_sigmask(how, &mod_set, oldset) : 0;
    }
    return orig_pthread_sigmask ? orig_pthread_sigmask(how, set, oldset) : 0;
}

int rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset, size_t sigsetsize) {
    static int (*orig_rt_sigprocmask)(int, const sigset_t *, sigset_t *, size_t) = NULL;
    if (!orig_rt_sigprocmask) orig_rt_sigprocmask = (int (*)(int, const sigset_t *, sigset_t *, size_t))dlsym(RTLD_NEXT, "rt_sigprocmask");
    if (set && (how == SIG_BLOCK || how == SIG_SETMASK)) {
        sigset_t mod_set;
        memcpy(&mod_set, set, sizeof(mod_set));
        sigdelset(&mod_set, SIGSYS);
        return orig_rt_sigprocmask ? orig_rt_sigprocmask(how, &mod_set, oldset, sigsetsize) : 0;
    }
    return orig_rt_sigprocmask ? orig_rt_sigprocmask(how, set, oldset, sigsetsize) : 0;
}

static const int g_crash_sigs[] = {SIGSEGV, SIGBUS, SIGILL, SIGABRT, SIGFPE};
#define CRASH_NSIG ((int)(sizeof(g_crash_sigs) / sizeof(g_crash_sigs[0])))
static struct sigaction g_crash_prev[CRASH_NSIG];

static void cortex_crash_handler(int sig, siginfo_t *info, void *ctx) {
    (void)ctx;
    init_cortex_hook();
    int pid = (int)getpid();
    const char *base = (g_cortex_root[0] != '\0') ? g_cortex_root : "";
    void *addr = info ? (void *)info->si_addr : NULL;
    int code = info ? info->si_code : -1;

    char path[PATH_MAX + 64];
    char hdr[384];
    int hn = snprintf(hdr, sizeof(hdr),
        "=== cortex native crash ===\n"
        "pid=%d sig=%d si_code=%d si_addr=%p\n"
        "root=%s\nexe=%s\n--- backtrace ---\n",
        pid, sig, code, addr, g_cortex_root, g_real_exe);
    int fd = -1;
    snprintf(path, sizeof(path), "%s/tmp/cortex-native-crash-%d-sig%d.log", base, pid, sig);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        snprintf(path, sizeof(path), "%s/cortex-native-crash-%d-sig%d.log", base, pid, sig);
        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    }
    if (fd >= 0) {
        if (hn > 0) { ssize_t w = write(fd, hdr, (size_t)hn); (void)w; }
        void *bt[64];
        int nbt = backtrace(bt, 64);
        backtrace_symbols_fd(bt, nbt, fd);
        close(fd);
    }
    {
        char line[192];
        int n = snprintf(line, sizeof(line),
            "\n[cortex] native crash: sig=%d si_code=%d si_addr=%p -> %s\n",
            sig, code, addr, path);
        if (n > 0) { ssize_t w = write(2, line, (size_t)n); (void)w; }
    }

    struct sigaction *prev = NULL;
    for (int i = 0; i < CRASH_NSIG; i++)
        if (g_crash_sigs[i] == sig) { prev = &g_crash_prev[i]; break; }
    sigset_t s; sigemptyset(&s); sigaddset(&s, sig);
    sigprocmask(SIG_UNBLOCK, &s, NULL);
    if (prev && prev->sa_handler != SIG_DFL && prev->sa_handler != SIG_IGN &&
        prev->sa_handler != NULL && prev->sa_sigaction != NULL) {
        int (*real_sa)(int, const struct sigaction *, struct sigaction *) = get_real_sigaction();
        if (real_sa) real_sa(sig, prev, NULL);
        raise(sig);
        return;
    }
    raise(sig);
    _exit(128 + sig);
}

__attribute__((constructor(102))) static void install_crash_handler(void) {
    int (*real_sa)(int, const struct sigaction *, struct sigaction *) = get_real_sigaction();
    if (!real_sa) return;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = cortex_crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    for (int i = 0; i < CRASH_NSIG; i++) {
        struct sigaction old;
        memset(&old, 0, sizeof(old));
        real_sa(g_crash_sigs[i], &sa, &old);
        g_crash_prev[i] = old;
    }
}

#endif /* !CORTEX_HOST_TEST */

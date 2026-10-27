#ifndef CORTEX_HOOK_COMMON_H
#define CORTEX_HOOK_COMMON_H

#include <limits.h>
#include <sys/types.h>
#include <unistd.h>

// Shared global state for the hook. Extern declarations only; definitions live
// in the files that own them (see cortex-hook.c which #includes all hook files).
#ifdef __cplusplus
extern "C" {
#endif

// Real executable path for the guest process
extern char g_real_exe[PATH_MAX];

// Cortex root directory
extern char g_cortex_root[PATH_MAX];
// Cortex root length (for fast strncmp in exec.c)
extern size_t g_cortex_root_len;

// A single zeroed environment block used to clear LD_PRELOAD etc.
extern char *g_cortex_empty_env[];

// Raw syscall seccomp notif fd (set by cortex-redirect wrapper)
extern int g_cortex_raw_notif_fd;

#ifdef __cplusplus
}
#endif

#endif /* CORTEX_HOOK_COMMON_H */

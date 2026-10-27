# cortex-redirect — seccomp supervisor for raw "/home" syscalls

## Why this exists

Static ELF binaries (e.g. kilo, a static Bun --compile binary) ignore `LD_PRELOAD`, so `libcortex-hook.so` never loads into them. Their Bun runtime makes raw `openat("/home")` syscalls that hit Android's real `/home` — which doesn't exist on Android — returning ENOENT ("realpath '/home' ENOENT").

Seccomp user-notification is the only mechanism that intercepts a static binary's raw syscalls. `cortex-redirect` is an unfiltered parent supervisor: the child installs a seccomp filter and `exec`s the target. Under `/home` paths, the parent redirects them to `$CORTEX_ROOT/home` and injects the resulting fd/stat back into the child. All other paths run the original syscall unchanged.

## What it handles

| Syscall under /home | Action |
|---|---|
| `openat` | Open `$CORTEX_ROOT/home...` in parent, `pidfd_getfd` the fd into child |
| `statx` / `newfstatat` | Stat `$CORTEX_ROOT/home...` in parent, write `struct` into child memory |
| Everything else | `SECCOMP_USER_NOTIF_FLAG_CONTINUE` — original syscall runs |

`accept()`/`accept4()` are intentionally NOT handled: the guest's own seccomp allows `accept4()` natively, and dynamic glibc tools already shim `accept()`→`accept4()` via `libcortex-hook.so`. This supervisor is for static ELFs only.

## Build

```bash
cd cortex-redirect
./build.sh
```

The script builds a glibc ELF (required so the guest's glibc `LD_PRELOAD` hook loads into this entry point) and copies the binary to `app/src/main/assets/cortex-redirect`.

## Deployment at runtime

`BootstrapManager.ensureRawSyscallRedirects()` deploys the asset as a wrapper named after the tool (e.g. `kilo`) with the real ELF kept as `kilo.real` beside it. The wrapper self-locates its `.real` sibling. `needsRedirect()` wraps only static ELF and Bun --compile ELFs — never dynamic glibc tools and never daemons.
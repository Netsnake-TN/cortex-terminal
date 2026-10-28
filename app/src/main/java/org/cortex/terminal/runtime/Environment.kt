package org.cortex.terminal.runtime

import android.content.Context
import java.io.File

object Environment {
    fun getCortexRoot(context: Context): File {
        return File(context.filesDir, "cortex")
    }

    fun getHomeDir(context: Context): File {
        return File(getCortexRoot(context), "home")
    }

    fun getUsrDir(context: Context): File {
        return File(getCortexRoot(context), "usr")
    }

    fun getTmpDir(context: Context): File {
        return File(getCortexRoot(context), "tmp")
    }

    fun getNativeLibDir(context: Context): File {
        return File(context.applicationInfo.nativeLibraryDir)
    }

    @Volatile private var cachedPathStr: String? = null
    @Volatile private var cachedLdPathStr: String? = null
    @Volatile private var cachedPreloadStr: String? = null
    @Volatile private var cachedCertFile: String? = null
    @Volatile private var cachedCertDir: String? = null
    @Volatile private var cachedTerminfo: String? = null
    @Volatile private var cachedTerminfoDirs: String? = null
    @Volatile private var cachedEffectiveTz: String? = null

    fun buildEnvironment(context: Context, rows: Int = 24, cols: Int = 80): Array<String> {
        val root = getCortexRoot(context).absolutePath
        val home = getHomeDir(context).absolutePath
        val tmp = getTmpDir(context).absolutePath

        val pathStr = synchronized(this) {
            cachedPathStr ?: run {
                val pathList = listOf(
                    "$home/.local/bin",
                    "$root/usr/local/bin",
                    "$root/bin",
                    "$root/usr/bin",
                    "$root/usr/local/sbin",
                    "$root/usr/sbin",
                    "$root/sbin",
                    // Android host commands (toybox) — e.g. curl — needed when the
                    // guest rootfs doesn't ship its own copy. Kept last so guest
                    // binaries take precedence over host ones.
                    "/system/bin"
                )
                pathList.joinToString(":").also { cachedPathStr = it }
            }
        }

        val ldPathStr = synchronized(this) {
            cachedLdPathStr ?: run {
                LibraryPath.forRoot(root).also { cachedLdPathStr = it }
            }
        }

        val glibcHooks = listOf(
            File(root, "usr/lib/libcortex-hook.so"),
            File(root, "lib/libcortex-hook.so")
        )
        val preloadStr = synchronized(this) {
            cachedPreloadStr ?: run {
                var hookLib = glibcHooks.firstOrNull { it.exists() }
                if (hookLib == null) {
                    BootstrapManager.ensureHookLibrary(context, File(root))
                    hookLib = glibcHooks.firstOrNull { it.exists() }
                }
                hookLib?.absolutePath ?: ""
            }.also { cachedPreloadStr = it }
        }

        val tz = try {
            java.util.TimeZone.getDefault()
        } catch (e: Exception) {
            null
        }
        val tzId = try { tz?.id ?: "UTC" } catch (e: Exception) { "UTC" }
        val now = System.currentTimeMillis()
        val offsetMillis = tz?.getOffset(now) ?: 0
        val totalMinutes = offsetMillis / 60000
        val posixSign = if (totalMinutes >= 0) "-" else "+"
        val absMinutes = Math.abs(totalMinutes)
        val hours = (absMinutes / 60).toInt()
        val mins = (absMinutes % 60).toInt()
        val shortName = try {
            val name = tz?.getDisplayName(tz.inDaylightTime(java.util.Date(now)), java.util.TimeZone.SHORT, java.util.Locale.US)
            if (!name.isNullOrEmpty() && name.all { it.isLetter() }) name else "GMT"
        } catch (e: Exception) {
            "GMT"
        }
        val stdName = when {
            shortName.length >= 3 && shortName.all { it.isLetter() } -> shortName
            totalMinutes >= 0 -> "<+%02d>".format(hours)
            else -> "<-%02d>".format(hours)
        }
        val posixTz = if (mins != 0) {
            "%s%s%d:%02d".format(stdName, posixSign, hours, mins)
        } else {
            "%s%s%d".format(stdName, posixSign, hours)
        }
        val effectiveTz = synchronized(this) {
            cachedEffectiveTz ?: run {
                if (File(root, "usr/share/zoneinfo/$tzId").exists()) tzId else posixTz
            }.also { cachedEffectiveTz = it }
        }

        val certFile = synchronized(this) {
            cachedCertFile ?: run {
                File(root, "etc/ssl/certs/ca-certificates.crt").absolutePath
            }.also { cachedCertFile = it }
        }
        val certDir = synchronized(this) {
            cachedCertDir ?: run {
                "${File(root, "etc/ssl/certs").absolutePath}:/system/etc/security/cacerts"
            }.also { cachedCertDir = it }
        }

        val terminfo = synchronized(this) {
            cachedTerminfo ?: run {
                "$root/usr/share/terminfo"
            }.also { cachedTerminfo = it }
        }
        val terminfoDirs = synchronized(this) {
            cachedTerminfoDirs ?: run {
                "$root/usr/share/terminfo:$root/lib/terminfo:$root/etc/terminfo:/usr/share/terminfo"
            }.also { cachedTerminfoDirs = it }
        }

        val envList = mutableListOf(
            "TERM=xterm-256color",
            "TERM_PROGRAM=cortex",
            "COLORTERM=truecolor",
            "HOME=$home",
            "CORTEX_ROOT=$root",
            "TMPDIR=$tmp",
            "PATH=$pathStr",
            "LD_LIBRARY_PATH=$ldPathStr",
            "GLIBC_TUNABLES=glibc.pthread.rseq=0",
            "LANG=C.UTF-8",
            "LC_ALL=C.UTF-8",
            "LOCPATH=$root/usr/lib/locale",
            "USER=cortex",
            "LOGNAME=cortex",
            "SHELL=/bin/bash",
            "HOSTNAME=cortex-android",
            "PS1=\\w $ ",
            "LD_BIND_NOW=1",
            "XDG_RUNTIME_DIR=$root/run/user/0",
            "DPKG_DEB_THREADS_MAX=1",
            "XZ_OPT=-T1",
            "XZ_DEFAULTS=-T1",
            "DEBIAN_FRONTEND=noninteractive",
            "DEBCONF_FRONTEND=noninteractive",
            "DEBCONF_NONINTERACTIVE_SEEN=true",
            "SSL_CERT_FILE=$certFile",
            "SSL_CERT_DIR=$certDir",
            "CURL_CA_BUNDLE=$certFile",
            "NODE_EXTRA_CA_CERTS=$certFile",
            "REQUESTS_CA_BUNDLE=$certFile",
            "TZDIR=$root/usr/share/zoneinfo",
            "TZ=$effectiveTz",
            "TERMINFO=$terminfo",
            "TERMINFO_DIRS=$terminfoDirs",
            "GODEBUG=netdns=cgo",
            "BROWSER=/usr/local/bin/xdg-open",
            "LINES=$rows",
            "COLUMNS=$cols"
        )

        if (preloadStr.isNotEmpty()) {
            envList.add("LD_PRELOAD=$preloadStr")
        }

        return envList.toTypedArray()
    }
}

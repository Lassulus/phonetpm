package dev.phonetpm.app

import android.content.Context

/** JNI entry points exported by libphonetpm_mobile.so (see crates/mobile/src/lib.rs). */
object Native {
    init {
        System.loadLibrary("phonetpm_mobile")
    }

    /** Registers the JVM + application context so iroh's DNS resolver can read system nameservers. */
    external fun nativeInit(ctx: Context)
}

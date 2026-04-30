package com.zovex.injector

import android.content.Context
import app.revanced.library.ApkSigner
import app.revanced.library.ApkUtils
import java.io.File
import java.util.Date

class ApkSigner(private val context: Context) {

    companion object {
        private const val KS_FILE  = "zovex_v3.keystore"
        private const val KS_ALIAS = "zovex"
        private const val KS_PASS  = "Zovex2024!"
    }

    fun sign(unsigned: File, out: File) {
        val ksFile = File(context.filesDir, KS_FILE)
        ensureKeystore(ksFile)

        val details = ApkUtils.KeyStoreDetails(
            keyStore      = ksFile,
            keyStorePassword = null,
            alias         = KS_ALIAS,
            password      = KS_PASS
        )
        ApkUtils.signApk(unsigned, out, KS_ALIAS, details)
    }

    private fun ensureKeystore(ksFile: File) {
        if (ksFile.exists()) return

        val expiry = Date(System.currentTimeMillis() + 3650L * 86400_000L)
        val pair   = ApkSigner.newPrivateKeyCertificatePair(KS_ALIAS, expiry)
        val ks     = ApkSigner.newKeyStore(
            setOf(ApkSigner.KeyStoreEntry(KS_ALIAS, KS_PASS, pair))
        )
        ksFile.outputStream().use { ks.store(it, null) }
    }
}

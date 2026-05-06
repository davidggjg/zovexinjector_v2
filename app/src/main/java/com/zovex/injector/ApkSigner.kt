package com.zovex.injector

import android.content.Context
import app.revanced.library.ApkSigner
import app.revanced.library.ApkUtils
import java.io.File
import java.util.Date

class ApkSigner(private val context: Context) {

    companion object {
        private const val KS_DIR   = "signing"
        private const val KS_FILE  = "manager.keystore"
        private const val KS_ALIAS = "ReVanced"
        private const val KS_PASS  = "ReVanced"
    }

    fun sign(unsigned: File, out: File) {
        val ksFile = context.getDir(KS_DIR, android.content.Context.MODE_PRIVATE)
            .resolve(KS_FILE)
        ensureKeystore(ksFile)
        val details = ApkUtils.KeyStoreDetails(
            keyStore         = ksFile,
            keyStorePassword = null,
            alias            = KS_ALIAS,
            password         = KS_PASS
        )
        ApkUtils.signApk(unsigned, out, KS_ALIAS, details)
    }

    private fun ensureKeystore(ksFile: File) {
        if (ksFile.exists()) return
        val expiry = Date(System.currentTimeMillis() + 8 * 365 * 24 * 60 * 60 * 1000L)
        val pair   = ApkSigner.newPrivateKeyCertificatePair(KS_ALIAS, expiry)
        val ks     = ApkSigner.newKeyStore(
            setOf(ApkSigner.KeyStoreEntry(KS_ALIAS, KS_PASS, pair))
        )
        ksFile.outputStream().use { ks.store(it, null) }
    }
}

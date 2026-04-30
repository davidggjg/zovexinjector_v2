package com.zovex.injector

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import app.revanced.library.ApkSigner
import app.revanced.library.ApkUtils
import java.io.File
import java.math.BigInteger
import java.security.*
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal

class ApkSigner(private val context: Context) {

    companion object {
        private const val KS_FILE  = "zovex_rvn.keystore"
        private const val KS_ALIAS = "ZovexKey"
        private const val KS_PASS  = "Zovex2024"
    }

    fun sign(unsigned: File, out: File) {
        ensureKeystore()
        val ksFile = File(context.filesDir, KS_FILE)
        val details = ApkUtils.KeyStoreDetails(
            keyStore = ksFile,
            keyStorePassword = null,
            alias = KS_ALIAS,
            password = KS_PASS
        )
        ApkUtils.signApk(unsigned, out, KS_ALIAS, details)
    }

    private fun ensureKeystore() {
        val ksFile = File(context.filesDir, KS_FILE)
        if (ksFile.exists()) return

        // צור keystore חדש עם ReVanced library
        val expiry = Date(System.currentTimeMillis() + 3650L * 86400_000L)
        val keyCertPair = ApkSigner.newPrivateKeyCertificatePair(KS_ALIAS, expiry)
        val ks = ApkSigner.newKeyStore(
            setOf(ApkSigner.KeyStoreEntry(KS_ALIAS, KS_PASS, keyCertPair))
        )
        ksFile.outputStream().use { ks.store(it, null) }
    }
}

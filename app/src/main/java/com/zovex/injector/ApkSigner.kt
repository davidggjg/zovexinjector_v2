package com.zovex.injector

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.android.apksig.ApkSigner as GoogleApkSigner
import com.android.apksig.apk.ApkFormatException
import java.io.File
import java.math.BigInteger
import java.security.*
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal

class ApkSigner(private val context: Context) {

    companion object {
        private const val AKS_ALIAS = "ZovexKey6"
    }

    fun sign(unsigned: File, out: File) {
        val (key, cert) = getOrCreateKeyPair()

        val signerConfig = GoogleApkSigner.SignerConfig.Builder(
            "CERT",
            key,
            listOf(cert)
        ).build()

        val signerEngine = GoogleApkSigner.Builder(listOf(signerConfig))
            .setInputApk(unsigned)
            .setOutputApk(out)
            .setV1SigningEnabled(true)
            .setV2SigningEnabled(true)
            .setV3SigningEnabled(true)
            .build()

        signerEngine.sign()
    }

    private fun getOrCreateKeyPair(): Pair<PrivateKey, X509Certificate> {
        val aks = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
        if (aks.containsAlias(AKS_ALIAS)) {
            return Pair(
                aks.getKey(AKS_ALIAS, null) as PrivateKey,
                aks.getCertificate(AKS_ALIAS) as X509Certificate
            )
        }
        val spec = KeyGenParameterSpec.Builder(
            AKS_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setKeySize(2048)
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .setCertificateSubject(X500Principal("CN=ZovexInjector, O=Zovex, C=IL"))
            .setCertificateSerialNumber(BigInteger.valueOf(System.currentTimeMillis()))
            .setCertificateNotBefore(java.util.Date(System.currentTimeMillis() - 86400_000L))
            .setCertificateNotAfter(java.util.Date(System.currentTimeMillis() + 3650L * 86400_000L))
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore").also {
            it.initialize(spec)
            it.generateKeyPair()
        }
        return Pair(
            aks.getKey(AKS_ALIAS, null) as PrivateKey,
            aks.getCertificate(AKS_ALIAS) as X509Certificate
        )
    }
}

package com.zovex.injector

import android.content.Context
import com.android.apksig.ApkSigner as GoogleApkSigner
import com.iyxan23.zipalignjava.ZipAlign
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.io.RandomAccessFile
import java.math.BigInteger
import java.security.*
import java.security.cert.X509Certificate
import java.util.Date

class ApkSigner(private val context: Context) {

    companion object {
        private const val KS_FILE  = "zovex_bc3.keystore"
        private const val KS_ALIAS = "zovex"
        private const val KS_PASS  = "zovex2024"
    }

    private val bc: Provider by lazy {
        Security.getProvider("BC")
            ?: BouncyCastleProvider().also { Security.insertProviderAt(it, 1) }
    }

    fun sign(unsigned: File, out: File) {
        val (key, cert) = getOrCreateKeyPair()

        // שלב 1: zipalign עם 4KB לקבצים רגילים ו-16KB ל-.so files
        val aligned = File(unsigned.parent, "aligned_${unsigned.name}")
        RandomAccessFile(unsigned, "r").use { raf ->
            aligned.outputStream().buffered().use { fos ->
                // 4 = alignment רגיל, 4096 = alignment ל-.so (16KB)
                ZipAlign.alignZip(raf, fos, 4, 4096)
            }
        }

        // שלב 2: חתימה V1+V2+V3
        val signerConfig = GoogleApkSigner.SignerConfig.Builder(
            "CERT", key, listOf(cert)
        ).build()

        GoogleApkSigner.Builder(listOf(signerConfig))
            .setInputApk(aligned)
            .setOutputApk(out)
            .setV1SigningEnabled(true)
            .setV2SigningEnabled(true)
            .setV3SigningEnabled(true)
            .setMinSdkVersion(26)
            .build()
            .sign()

        aligned.delete()
    }

    private fun getOrCreateKeyPair(): Pair<PrivateKey, X509Certificate> {
        val ksFile = File(context.filesDir, KS_FILE)

        if (ksFile.exists()) {
            try {
                val ks = KeyStore.getInstance("BKS", bc).also {
                    ksFile.inputStream().use { s -> it.load(s, KS_PASS.toCharArray()) }
                }
                val key  = ks.getKey(KS_ALIAS, KS_PASS.toCharArray()) as PrivateKey
                val cert = ks.getCertificate(KS_ALIAS) as X509Certificate
                return Pair(key, cert)
            } catch (e: Exception) {
                ksFile.delete()
            }
        }

        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048, SecureRandom())
        val kp = kpg.generateKeyPair()

        val now     = System.currentTimeMillis()
        val subject = X500Name("CN=ZovexInjector, O=Zovex, C=IL")
        val certHolder = JcaX509v3CertificateBuilder(
            subject,
            BigInteger.valueOf(now),
            Date(now - 86400_000L),
            Date(now + 3650L * 86400_000L),
            subject,
            kp.public
        ).build(
            JcaContentSignerBuilder("SHA256withRSA").build(kp.private)
        )

        val cert = JcaX509CertificateConverter().getCertificate(certHolder)

        val ks = KeyStore.getInstance("BKS", bc).also { it.load(null) }
        ks.setKeyEntry(KS_ALIAS, kp.private, KS_PASS.toCharArray(), arrayOf(cert))
        ksFile.outputStream().use { ks.store(it, KS_PASS.toCharArray()) }

        return Pair(kp.private, cert)
    }
}

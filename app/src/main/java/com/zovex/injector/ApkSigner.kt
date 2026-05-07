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
        private const val KS_FILE = "zovex_bc.keystore"
        private const val KS_ALIAS = "zovex"
        private const val KS_PASS = "zovex2024"

        init {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        }
    }

    fun sign(unsigned: File, out: File) {
        val (key, cert) = getOrCreateKeyPair()

        // שלב 1: zipalign
        val aligned = File(unsigned.parent, "aligned_${unsigned.name}")
        RandomAccessFile(unsigned, "r").use { raf ->
            aligned.outputStream().buffered().use { fos ->
                ZipAlign.alignZip(raf, fos)
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
            .build()
            .sign()

        aligned.delete()
    }

    private fun getOrCreateKeyPair(): Pair<PrivateKey, X509Certificate> {
        val ksFile = File(context.filesDir, KS_FILE)

        if (ksFile.exists()) {
            val ks = KeyStore.getInstance("BKS", "BC").also {
                ksFile.inputStream().use { s -> it.load(s, KS_PASS.toCharArray()) }
            }
            val key = ks.getKey(KS_ALIAS, KS_PASS.toCharArray()) as PrivateKey
            val cert = ks.getCertificate(KS_ALIAS) as X509Certificate
            return Pair(key, cert)
        }

        // צור RSA key pair עם BouncyCastle
        val kpg = KeyPairGenerator.getInstance("RSA", "BC")
        kpg.initialize(2048, SecureRandom())
        val kp = kpg.generateKeyPair()

        // צור X509 certificate עם BouncyCastle
        val now = System.currentTimeMillis()
        val subject = X500Name("CN=ZovexInjector, O=Zovex, C=IL")
        val certBuilder = JcaX509v3CertificateBuilder(
            subject,
            BigInteger.valueOf(now),
            Date(now - 86400_000L),
            Date(now + 3650L * 86400_000L),
            subject,
            kp.public
        )
        val signer = JcaContentSignerBuilder("SHA256withRSA")
            .setProvider("BC")
            .build(kp.private)
        val cert = JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(certBuilder.build(signer))

        // שמור ב-BKS keystore
        val ks = KeyStore.getInstance("BKS", "BC").also { it.load(null) }
        ks.setKeyEntry(KS_ALIAS, kp.private, KS_PASS.toCharArray(), arrayOf(cert))
        ksFile.outputStream().use { ks.store(it, KS_PASS.toCharArray()) }

        return Pair(kp.private, cert)
    }
}

package com.zovex.injector

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.io.File
import java.math.BigInteger
import java.security.*
import java.security.cert.X509Certificate
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import javax.security.auth.x500.X500Principal

class ApkSigner(private val context: Context) {

    companion object {
        private const val KS_FILE   = "zovex2.keystore"
        private const val KS_ALIAS  = "zovex"
        private const val KS_PASS   = "Zovex_2024"
        private const val AKS_ALIAS = "ZovexSigningKey"
    }

    fun sign(unsigned: File, out: File) {
        val (key, cert) = getOrCreateKeyPair()
        val mf  = buildManifest(unsigned)
        val sf  = buildSF(mf)
        val sig = Signature.getInstance("SHA256withRSA").also {
            it.initSign(key); it.update(sf)
        }.sign()
        val rsa = buildPkcs7(cert, sig)
        ZipOutputStream(out.outputStream().buffered()).use { zos ->
            zos.setLevel(6)
            fun put(n: String, d: ByteArray) {
                zos.putNextEntry(ZipEntry(n)); zos.write(d); zos.closeEntry()
            }
            put("META-INF/MANIFEST.MF", mf)
            put("META-INF/CERT.SF", sf)
            put("META-INF/CERT.RSA", rsa)
            ZipFile(unsigned).use { zip ->
                zip.entries().asSequence().forEach { e ->
                    zos.putNextEntry(ZipEntry(e.name))
                    zip.getInputStream(e).use { it.copyTo(zos) }
                    zos.closeEntry()
                }
            }
        }
    }

    /**
     * מחזיר (PrivateKey, X509Certificate) מ-Android Keystore
     * יוצר אם לא קיים — Android Keystore מייצר certificate תקין אוטומטית
     */
    private fun getOrCreateKeyPair(): Pair<PrivateKey, X509Certificate> {
        val aks = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }

        // נסה לטעון קיים
        if (aks.containsAlias(AKS_ALIAS)) {
            val key  = aks.getKey(AKS_ALIAS, null) as PrivateKey
            val cert = aks.getCertificate(AKS_ALIAS) as X509Certificate
            return Pair(key, cert)
        }

        // צור חדש
        val spec = KeyGenParameterSpec.Builder(
            AKS_ALIAS,
            KeyProperties.PURPOSE_SIGN
        )
            .setKeySize(2048)
            .setDigests(KeyProperties.DIGEST_SHA256)
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

        val key  = aks.getKey(AKS_ALIAS, null) as PrivateKey
        val cert = aks.getCertificate(AKS_ALIAS) as X509Certificate
        return Pair(key, cert)
    }

    private fun buildManifest(apk: File): ByteArray {
        val sb = StringBuilder("Manifest-Version: 1.0\r\nCreated-By: ZovexInjector\r\n\r\n")
        ZipFile(apk).use { zip ->
            zip.entries().asSequence()
                .filter { !it.name.startsWith("META-INF/") }
                .sortedBy { it.name }
                .forEach { e ->
                    val md = MessageDigest.getInstance("SHA-256")
                    zip.getInputStream(e).use { md.update(it.readBytes()) }
                    sb.append("Name: ${e.name}\r\nSHA-256-Digest: ${
                        Base64.encodeToString(md.digest(), Base64.NO_WRAP)
                    }\r\n\r\n")
                }
        }
        return sb.toString().toByteArray()
    }

    private fun buildSF(mf: ByteArray): ByteArray {
        val d = Base64.encodeToString(
            MessageDigest.getInstance("SHA-256").digest(mf), Base64.NO_WRAP)
        return "Signature-Version: 1.0\r\nCreated-By: ZovexInjector\r\nSHA-256-Digest-Manifest: $d\r\n\r\n"
            .toByteArray()
    }

    private fun buildPkcs7(cert: X509Certificate, sig: ByteArray): ByteArray {
        val cd = cert.encoded
        fun len(n: Int) = when {
            n < 0x80  -> byteArrayOf(n.toByte())
            n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
            else      -> byteArrayOf(0x82.toByte(), (n ushr 8).toByte(), (n and 0xFF).toByte())
        }
        fun w(t: Int, d: ByteArray) = byteArrayOf(t.toByte()) + len(d.size) + d
        fun seq(vararg p: ByteArray) = w(0x30, p.reduce { a, b -> a + b })
        fun set(vararg p: ByteArray) = w(0x31, p.reduce { a, b -> a + b })
        fun oid(vararg v: Int) = w(0x06, v.map { it.toByte() }.toByteArray())
        fun i1(v: Int) = byteArrayOf(0x02, 0x01, v.toByte())
        fun oct(b: ByteArray) = w(0x04, b)
        fun ctx(t: Int, b: ByteArray) = w(0xA0 or t, b)
        val nil = byteArrayOf(0x05, 0x00)
        val sha = oid(0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01)
        val rsa = oid(0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01)
        val d7  = oid(0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x01)
        val sd  = oid(0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x02)
        val sn  = cert.serialNumber.toByteArray().let { byteArrayOf(0x02) + len(it.size) + it }
        val si  = seq(i1(1), seq(cert.issuerX500Principal.encoded, sn),
                      seq(sha, nil), seq(rsa, nil), oct(sig))
        val inner = seq(i1(1), set(seq(sha, nil)), seq(d7), ctx(0, cd), set(si))
        return seq(sd, ctx(0, inner))
    }
                              }

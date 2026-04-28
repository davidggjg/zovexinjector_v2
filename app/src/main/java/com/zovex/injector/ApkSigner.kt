package com.zovex.injector

import android.content.Context
import android.util.Base64
import java.io.File
import java.math.BigInteger
import java.security.*
import java.security.cert.X509Certificate
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

class ApkSigner(private val context: Context) {

    companion object {
        private const val KS_FILE  = "zovex.keystore"
        private const val KS_ALIAS = "zovex"
        private const val KS_PASS  = "Zovex_2024"
    }

    fun sign(unsigned: File, out: File) {
        ensureKeystore()
        val ks = KeyStore.getInstance("PKCS12")
        File(context.filesDir, KS_FILE).inputStream().use { ks.load(it, KS_PASS.toCharArray()) }
        val key  = ks.getKey(KS_ALIAS, KS_PASS.toCharArray()) as PrivateKey
        val cert = ks.getCertificateChain(KS_ALIAS)[0] as X509Certificate
        val mf   = buildManifest(unsigned)
        val sf   = buildSF(mf)
        val sig  = Signature.getInstance("SHA256withRSA").also { it.initSign(key); it.update(sf) }.sign()
        val rsa  = buildPkcs7(cert, sig)
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
        val nil    = byteArrayOf(0x05, 0x00)
        val sha    = oid(0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01)
        val rsa    = oid(0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01)
        val d7     = oid(0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x01)
        val sd     = oid(0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x02)
        val sn     = cert.serialNumber.toByteArray().let { byteArrayOf(0x02) + len(it.size) + it }
        val si     = seq(i1(1), seq(cert.issuerX500Principal.encoded, sn),
                        seq(sha, nil), seq(rsa, nil), oct(sig))
        val inner  = seq(i1(1), set(seq(sha, nil)), seq(d7), ctx(0, cd), set(si))
        return seq(sd, ctx(0, inner))
    }

    private fun ensureKeystore() {
        val f = File(context.filesDir, KS_FILE)
        if (f.exists()) return

        val kpg = KeyPairGenerator.getInstance("RSA").also { it.initialize(2048, SecureRandom()) }
        val kp  = kpg.generateKeyPair()
        val cert = generateCert(kp)

        KeyStore.getInstance("PKCS12").also {
            it.load(null, null)
            it.setKeyEntry(KS_ALIAS, kp.private, KS_PASS.toCharArray(), arrayOf(cert))
            f.outputStream().use { os -> it.store(os, KS_PASS.toCharArray()) }
        }
    }

    private fun generateCert(kp: KeyPair): X509Certificate {
        // ניסיון 1: BouncyCastle (קיים באנדרואיד)
        return try {
            generateViaBC(kp)
        } catch (e1: Exception) {
            // ניסיון 2: sun.security.x509
            try {
                generateViaSun(kp)
            } catch (e2: Exception) {
                throw RuntimeException("לא ניתן ליצור certificate: ${e1.message} / ${e2.message}")
            }
        }
    }

    private fun generateViaBC(kp: KeyPair): X509Certificate {
        val bc  = "org.bouncycastle"
        val gen = Class.forName("$bc.x509.X509V3CertificateGenerator").newInstance()
        val g   = gen.javaClass
        val x500 = Class.forName("$bc.asn1.x500.X500Name")
            .getConstructor(String::class.java)
            .newInstance("CN=ZovexInjector, O=Zovex, C=IL")
        val now = java.util.Date()
        val exp = java.util.Date(now.time + 3650L * 86400_000L)
        g.getMethod("setSerialNumber", BigInteger::class.java)
            .invoke(gen, BigInteger(64, SecureRandom()))
        for (m in listOf("setIssuerDN", "setSubjectDN"))
            g.getMethod(m, Class.forName("$bc.asn1.x500.X500Name")).invoke(gen, x500)
        g.getMethod("setNotBefore", java.util.Date::class.java).invoke(gen, now)
        g.getMethod("setNotAfter",  java.util.Date::class.java).invoke(gen, exp)
        g.getMethod("setPublicKey", PublicKey::class.java).invoke(gen, kp.public)
        g.getMethod("setSignatureAlgorithm", String::class.java)
            .invoke(gen, "SHA256WithRSAEncryption")
        return g.getMethod("generate", PrivateKey::class.java)
            .invoke(gen, kp.private) as X509Certificate
    }

    private fun generateViaSun(kp: KeyPair): X509Certificate {
        val ci  = Class.forName("sun.security.x509.X509CertInfo").newInstance()
        val c   = ci.javaClass
        val now = System.currentTimeMillis()
        fun cls(s: String) = Class.forName(s)
        val v = cls("sun.security.x509.CertificateValidity")
            .getConstructor(java.util.Date::class.java, java.util.Date::class.java)
            .newInstance(java.util.Date(now), java.util.Date(now + 3650L * 86400_000L))
        val n = cls("sun.security.x509.X500Name")
            .getConstructor(String::class.java)
            .newInstance("CN=ZovexInjector, O=Zovex, C=IL")
        val a = cls("sun.security.x509.AlgorithmId")
            .getMethod("get", String::class.java).invoke(null, "SHA256withRSA")
        val set = c.getMethod("set", String::class.java, Any::class.java)
        set.invoke(ci, "validity", v)
        set.invoke(ci, "serialNumber",
            cls("sun.security.x509.CertificateSerialNumber")
                .getConstructor(BigInteger::class.java)
                .newInstance(BigInteger(64, SecureRandom())))
        set.invoke(ci, "subject",
            cls("sun.security.x509.CertificateSubjectName")
                .getConstructor(cls("sun.security.x509.X500Name")).newInstance(n))
        set.invoke(ci, "issuer",
            cls("sun.security.x509.CertificateIssuerName")
                .getConstructor(cls("sun.security.x509.X500Name")).newInstance(n))
        set.invoke(ci, "key",
            cls("sun.security.x509.CertificateX509Key")
                .getConstructor(PublicKey::class.java).newInstance(kp.public))
        set.invoke(ci, "algorithmID",
            cls("sun.security.x509.CertificateAlgorithmId")
                .getConstructor(cls("sun.security.x509.AlgorithmId")).newInstance(a))
        set.invoke(ci, "version",
            cls("sun.security.x509.CertificateVersion")
                .getConstructor(Int::class.java).newInstance(2))
        val cert = cls("sun.security.x509.X509CertImpl")
            .getConstructor(cls("sun.security.x509.X509CertInfo")).newInstance(ci)
        cert.javaClass.getMethod("sign", PrivateKey::class.java, String::class.java)
            .invoke(cert, kp.private, "SHA256withRSA")
        return cert as X509Certificate
    }
                              }

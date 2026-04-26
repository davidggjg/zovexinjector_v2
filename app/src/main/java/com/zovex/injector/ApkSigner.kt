package com.zovex.injector

import android.content.Context
import android.util.Base64
import android.util.Log
import java.io.File
import java.math.BigInteger
import java.security.*
import java.security.cert.X509Certificate
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * חתימת APK — ללא BouncyCastle
 * משתמש ב-Android Keystore API ישירות
 */
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

        val mf  = buildManifest(unsigned)
        val sf  = buildSF(mf)
        val sig = Signature.getInstance("SHA256withRSA").also { it.initSign(key); it.update(sf) }.sign()
        val rsa = buildPkcs7(cert, sig)

        ZipOutputStream(out.outputStream().buffered()).use { zos ->
            zos.setLevel(6)
            fun put(name: String, data: ByteArray) {
                zos.putNextEntry(ZipEntry(name)); zos.write(data); zos.closeEntry()
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
        Log.d("ApkSigner", "חתום ✅")
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
                    sb.append("Name: ${e.name}\r\nSHA-256-Digest: ${Base64.encodeToString(md.digest(), Base64.NO_WRAP)}\r\n\r\n")
                }
        }
        return sb.toString().toByteArray()
    }

    private fun buildSF(mf: ByteArray): ByteArray {
        val d = Base64.encodeToString(MessageDigest.getInstance("SHA-256").digest(mf), Base64.NO_WRAP)
        return "Signature-Version: 1.0\r\nCreated-By: ZovexInjector\r\nSHA-256-Digest-Manifest: $d\r\n\r\n".toByteArray()
    }

    private fun buildPkcs7(cert: X509Certificate, sig: ByteArray): ByteArray {
        val certDer = cert.encoded
        fun len(n: Int) = when {
            n < 0x80  -> byteArrayOf(n.toByte())
            n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
            else      -> byteArrayOf(0x82.toByte(), (n ushr 8).toByte(), (n and 0xFF).toByte())
        }
        fun w(t: Int, d: ByteArray) = byteArrayOf(t.toByte()) + len(d.size) + d
        fun seq(vararg p: ByteArray) = w(0x30, p.reduce { a, b -> a + b })
        fun set(vararg p: ByteArray) = w(0x31, p.reduce { a, b -> a + b })
        fun oid(vararg v: Int)        = w(0x06, v.map { it.toByte() }.toByteArray())
        fun int1(v: Int)              = byteArrayOf(0x02, 0x01, v.toByte())
        fun octet(b: ByteArray)       = w(0x04, b)
        fun ctx(t: Int, b: ByteArray) = w(0xA0 or t, b)
        val nil    = byteArrayOf(0x05, 0x00)
        val sha256 = oid(0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01)
        val rsa    = oid(0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01)
        val d7     = oid(0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x01)
        val sd     = oid(0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x02)
        val serial = cert.serialNumber.toByteArray().let { byteArrayOf(0x02) + len(it.size) + it }
        val si    = seq(int1(1), seq(cert.issuerX500Principal.encoded, serial), seq(sha256,nil), seq(rsa,nil), octet(sig))
        val inner = seq(int1(1), set(seq(sha256,nil)), seq(d7), ctx(0,certDer), set(si))
        return seq(sd, ctx(0, inner))
    }

    private fun ensureKeystore() {
        val f = File(context.filesDir, KS_FILE)
        if (f.exists()) return

        val kpg = KeyPairGenerator.getInstance("RSA").also { it.initialize(2048, SecureRandom()) }
        val kp  = kpg.generateKeyPair()
        val cert = generateSelfSignedCert(kp)

        KeyStore.getInstance("PKCS12").also {
            it.load(null, null)
            it.setKeyEntry(KS_ALIAS, kp.private, KS_PASS.toCharArray(), arrayOf(cert))
            f.outputStream().use { os -> it.store(os, KS_PASS.toCharArray()) }
        }
    }

    /**
     * יוצר self-signed certificate ללא BouncyCastle
     * משתמש ב-sun.security.x509 שזמין ב-Android
     */
    private fun generateSelfSignedCert(kp: KeyPair): X509Certificate {
        return try {
            // נסה דרך sun.security.x509 (זמין ברוב מכשירי Android)
            generateViaSunX509(kp)
        } catch (e: Exception) {
            Log.w("ApkSigner", "sun.security.x509 נכשל: ${e.message}, מנסה BouncyCastle...")
            try {
                generateViaBouncyCastle(kp)
            } catch (e2: Exception) {
                Log.w("ApkSigner", "BouncyCastle נכשל: ${e2.message}, מנסה Conscrypt...")
                generateViaConscrypt(kp)
            }
        }
    }

    private fun generateViaSunX509(kp: KeyPair): X509Certificate {
        val certInfo = Class.forName("sun.security.x509.X509CertInfo").newInstance()
        val cls = certInfo.javaClass

        val now = System.currentTimeMillis()
        val validity = Class.forName("sun.security.x509.CertificateValidity")
            .getConstructor(java.util.Date::class.java, java.util.Date::class.java)
            .newInstance(java.util.Date(now), java.util.Date(now + 10L * 365 * 24 * 60 * 60 * 1000))

        val x500Name = Class.forName("sun.security.x509.X500Name")
            .getConstructor(String::class.java)
            .newInstance("CN=ZovexInjector, O=Zovex, C=IL")

        val algId = Class.forName("sun.security.x509.AlgorithmId")
            .getMethod("get", String::class.java)
            .invoke(null, "SHA256withRSA")

        cls.getMethod("set", String::class.java, Any::class.java).let { set ->
            set.invoke(certInfo, "validity", validity)
            set.invoke(certInfo, "serialNumber",
                Class.forName("sun.security.x509.CertificateSerialNumber")
                    .getConstructor(BigInteger::class.java)
                    .newInstance(BigInteger(64, SecureRandom())))
            set.invoke(certInfo, "subject",
                Class.forName("sun.security.x509.CertificateSubjectName")
                    .getConstructor(Class.forName("sun.security.x509.X500Name"))
                    .newInstance(x500Name))
            set.invoke(certInfo, "issuer",
                Class.forName("sun.security.x509.CertificateIssuerName")
                    .getConstructor(Class.forName("sun.security.x509.X500Name"))
                    .newInstance(x500Name))
            set.invoke(certInfo, "key",
                Class.forName("sun.security.x509.CertificateX509Key")
                    .getConstructor(PublicKey::class.java)
                    .newInstance(kp.public))
            set.invoke(certInfo, "algorithmID",
                Class.forName("sun.security.x509.CertificateAlgorithmId")
                    .getConstructor(Class.forName("sun.security.x509.AlgorithmId"))
                    .newInstance(algId))
            set.invoke(certInfo, "version",
                Class.forName("sun.security.x509.CertificateVersion")
                    .getConstructor(Int::class.java)
                    .newInstance(2))
        }

        val cert = Class.forName("sun.security.x509.X509CertImpl")
            .getConstructor(Class.forName("sun.security.x509.X509CertInfo"))
            .newInstance(certInfo)
        cert.javaClass.getMethod("sign", PrivateKey::class.java, String::class.java)
            .invoke(cert, kp.private, "SHA256withRSA")

        return cert as X509Certificate
    }

    private fun generateViaBouncyCastle(kp: KeyPair): X509Certificate {
        val bc  = "org.bouncycastle"
        val gen = Class.forName("$bc.x509.X509V3CertificateGenerator").newInstance()
        val cls = gen.javaClass
        val x500 = Class.forName("$bc.asn1.x500.X500Name")
            .getConstructor(String::class.java).newInstance("CN=ZovexInjector,O=Zovex,C=IL")
        val now  = java.util.Date()
        val exp  = java.util.Date(now.time + 3650L * 86400_000L)
        cls.getMethod("setSerialNumber", BigInteger::class.java).invoke(gen, BigInteger(64, SecureRandom()))
        for (m in listOf("setIssuerDN", "setSubjectDN"))
            cls.getMethod(m, Class.forName("$bc.asn1.x500.X500Name")).invoke(gen, x500)
        cls.getMethod("setNotBefore", java.util.Date::class.java).invoke(gen, now)
        cls.getMethod("setNotAfter",  java.util.Date::class.java).invoke(gen, exp)
        cls.getMethod("setPublicKey", PublicKey::class.java).invoke(gen, kp.public)
        cls.getMethod("setSignatureAlgorithm", String::class.java).invoke(gen, "SHA256WithRSAEncryption")
        return cls.getMethod("generate", PrivateKey::class.java).invoke(gen, kp.private) as X509Certificate
    }

    private fun generateViaConscrypt(kp: KeyPair): X509Certificate {
        // Fallback אחרון — יצירת certificate מינימלי ידנית
        val tbsCert = buildTBSCertificate(kp)
        val sig = Signature.getInstance("SHA256withRSA").also {
            it.initSign(kp.private); it.update(tbsCert)
        }.sign()

        fun len(n: Int) = when {
            n < 0x80  -> byteArrayOf(n.toByte())
            n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
            else      -> byteArrayOf(0x82.toByte(), (n ushr 8).toByte(), (n and 0xFF).toByte())
        }
        fun w(t: Int, d: ByteArray) = byteArrayOf(t.toByte()) + len(d.size) + d
        fun seq(vararg p: ByteArray) = w(0x30, p.reduce { a, b -> a + b })
        fun oid(vararg v: Int) = w(0x06, v.map { it.toByte() }.toByteArray())
        val nil = byteArrayOf(0x05, 0x00)
        val sha256rsa = oid(0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B)
        val certDer = seq(tbsCert, seq(sha256rsa, nil), w(0x03, byteArrayOf(0x00) + sig))

        val cf = java.security.cert.CertificateFactory.getInstance("X.509")
        return cf.generateCertificate(certDer.inputStream()) as X509Certificate
    }

    private fun buildTBSCertificate(kp: KeyPair): ByteArray {
        fun len(n: Int) = when {
            n < 0x80  -> byteArrayOf(n.toByte())
            n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
            else      -> byteArrayOf(0x82.toByte(), (n ushr 8).toByte(), (n and 0xFF).toByte())
        }
        fun w(t: Int, d: ByteArray) = byteArrayOf(t.toByte()) + len(d.size) + d
        fun seq(vararg p: ByteArray) = w(0x30, p.reduce { a, b -> a + b })
        fun oid(vararg v: Int) = w(0x06, v.map { it.toByte() }.toByteArray())
        fun int1(v: Int) = byteArrayOf(0x02, 0x01, v.toByte())
        fun ctx(t: Int, b: ByteArray) = w(0xA0 or t, b)
        val nil = byteArrayOf(0x05, 0x00)

        val now = System.currentTimeMillis()
        fun time(ms: Long): ByteArray {
            val sdf = java.text.SimpleDateFormat("yyMMddHHmmss'Z'", java.util.Locale.US)
            sdf.timeZone = java.util.TimeZone.getTimeZone("UTC")
            val s = sdf.format(java.util.Date(ms))
            return w(0x17, s.toByteArray())
        }

        val sha256rsa = oid(0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B)
        val name = seq(seq(seq(
            oid(0x55,0x04,0x03),
            w(0x0C, "ZovexInjector".toByteArray())
        )))

        return seq(
            ctx(0, int1(2)),
            BigInteger(64, SecureRandom()).toByteArray().let { byteArrayOf(0x02) + len(it.size) + it },
            seq(sha256rsa, nil),
            name,
            seq(time(now - 1000), time(now + 3650L * 86400_000L)),
            name,
            kp.public.encoded
        )
    }
}

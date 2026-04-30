package com.zovex.injector

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.io.File
import java.io.RandomAccessFile
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.*
import java.security.cert.X509Certificate
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import javax.security.auth.x500.X500Principal

class ApkSigner(private val context: Context) {

    companion object {
        private const val AKS_ALIAS = "ZovexSigningKey3"

        // APK Signing Block magic
        private val APK_SIG_BLOCK_MAGIC_HI = 0x3234206b636f6c42L
        private val APK_SIG_BLOCK_MAGIC_LO = 0x20676e6953204b50L
        private const val APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a
        private const val APK_SIG_BLOCK_MIN_SIZE = 32
    }

    fun sign(unsigned: File, out: File) {
        val (key, cert) = getOrCreateKeyPair()

        // שלב 1: חתימת V1 (JAR signing) — נדרשת לתאימות
        val v1Signed = File(unsigned.parent, "v1_${unsigned.name}")
        signV1(unsigned, v1Signed, key, cert)

        // שלב 2: חתימת V2 (APK Signature Scheme v2) — נדרשת לסמסונג
        signV2(v1Signed, out, key, cert)

        v1Signed.delete()
    }

    // ── Android Keystore ───────────────────────────────────────

    private fun getOrCreateKeyPair(): Pair<PrivateKey, X509Certificate> {
        val aks = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
        if (aks.containsAlias(AKS_ALIAS)) {
            val key  = aks.getKey(AKS_ALIAS, null) as PrivateKey
            val cert = aks.getCertificate(AKS_ALIAS) as X509Certificate
            return Pair(key, cert)
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
        val key  = aks.getKey(AKS_ALIAS, null) as PrivateKey
        val cert = aks.getCertificate(AKS_ALIAS) as X509Certificate
        return Pair(key, cert)
    }

    // ── V1 Signing (JAR) ───────────────────────────────────────

    private fun signV1(unsigned: File, out: File, key: PrivateKey, cert: X509Certificate) {
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
            n < 0x80    -> byteArrayOf(n.toByte())
            n < 0x100   -> byteArrayOf(0x81.toByte(), n.toByte())
            n < 0x10000 -> byteArrayOf(0x82.toByte(), (n ushr 8).toByte(), (n and 0xFF).toByte())
            else        -> byteArrayOf(0x83.toByte(), (n ushr 16).toByte(),
                (n ushr 8 and 0xFF).toByte(), (n and 0xFF).toByte())
        }
        fun w(t: Int, d: ByteArray) = byteArrayOf(t.toByte()) + len(d.size) + d
        fun seq(vararg p: ByteArray) = w(0x30, p.reduce { a, b -> a + b })
        fun set(vararg p: ByteArray) = w(0x31, p.reduce { a, b -> a + b })
        fun oid(vararg v: Int) = w(0x06, v.map { it.toByte() }.toByteArray())
        fun i1(v: Int) = byteArrayOf(0x02, 0x01, v.toByte())
        fun oct(b: ByteArray) = w(0x04, b)
        fun ctx(t: Int, b: ByteArray) = w(0xA0 or t, b)
        val nil       = byteArrayOf(0x05, 0x00)
        val sha256    = oid(0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01)
        val rsaEnc    = oid(0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01)
        val dataOid   = oid(0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x01)
        val signedOid = oid(0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x02)
        val serialBytes = cert.serialNumber.toByteArray()
        val serialFixed = if (serialBytes[0] < 0) byteArrayOf(0x00) + serialBytes else serialBytes
        val serialDer   = byteArrayOf(0x02) + len(serialFixed.size) + serialFixed
        val signerInfo  = seq(i1(1),
            seq(cert.issuerX500Principal.encoded, serialDer),
            seq(sha256, nil), seq(rsaEnc, nil), oct(sig))
        val innerData = seq(i1(1), set(seq(sha256, nil)), seq(dataOid), ctx(0, cd), set(signerInfo))
        return seq(signedOid, ctx(0, innerData))
    }

    // ── V2 Signing (APK Signature Scheme v2) ──────────────────

    private fun signV2(input: File, output: File, key: PrivateKey, cert: X509Certificate) {
        // קרא את ה-APK
        val apkBytes = input.readBytes()

        // מצא את ה-EOCD (End of Central Directory)
        val eocdOffset = findEocdOffset(apkBytes)
            ?: run { input.copyTo(output, overwrite = true); return }

        val eocd = apkBytes.copyOfRange(eocdOffset, apkBytes.size)

        // מצא את תחילת ה-Central Directory
        val cdOffset = ByteBuffer.wrap(eocd, 16, 4)
            .order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL

        // שלושת החלקים לחתימה
        val beforeCd   = apkBytes.copyOfRange(0, cdOffset.toInt())
        val centralDir = apkBytes.copyOfRange(cdOffset.toInt(), eocdOffset)

        // שנה ה-EOCD כך שה-CD offset יצביע אחרי ה-signing block
        val modifiedEocd = eocd.copyOf()

        // חשב digest של כל החלקים
        fun chunkDigest(data: ByteArray): ByteArray {
            val md = MessageDigest.getInstance("SHA-256")
            // כל chunk מתחיל ב-0xa5
            var offset = 0
            val chunkSize = 1024 * 1024 // 1MB chunks
            val chunkDigests = mutableListOf<ByteArray>()
            while (offset < data.size) {
                val end = minOf(offset + chunkSize, data.size)
                val chunkMd = MessageDigest.getInstance("SHA-256")
                chunkMd.update(0xa5.toByte())
                chunkMd.update(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
                    .putInt(end - offset).array())
                chunkMd.update(data, offset, end - offset)
                chunkDigests.add(chunkMd.digest())
                offset = end
            }
            // Top-level digest
            md.update(0x5a.toByte())
            md.update(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(chunkDigests.size).array())
            chunkDigests.forEach { md.update(it) }
            return md.digest()
        }

        val d1 = chunkDigest(beforeCd)
        val d2 = chunkDigest(centralDir)
        val d3 = chunkDigest(modifiedEocd)

        // בנה את ה-signed data
        val certEncoded = cert.encoded
        fun intLE(v: Int) = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(v).array()
        fun longLE(v: Long) = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(v).array()
        fun lenPrefixed(vararg parts: ByteArray): ByteArray {
            val data = parts.reduce { a, b -> a + b }
            return intLE(data.size) + data
        }

        // Digest: algorithm=SHA256_RSA_PKCS1_V1_5 (0x0103), digest
        val digestAlgoId = intLE(0x0103) // SHA256withRSA
        val combinedDigest: ByteArray = run {
            val md = MessageDigest.getInstance("SHA-256")
            md.update(0x5a.toByte())
            md.update(intLE(3)) // 3 sections
            md.update(intLE(d1.size)); md.update(d1)
            md.update(intLE(d2.size)); md.update(d2)
            md.update(intLE(d3.size)); md.update(d3)
            md.digest()
        }

        val digestEntry   = lenPrefixed(digestAlgoId, intLE(combinedDigest.size) + combinedDigest)
        val certEntry     = lenPrefixed(intLE(certEncoded.size) + certEncoded)
        val signedData    = lenPrefixed(
            lenPrefixed(digestEntry),   // digests
            lenPrefixed(certEntry),     // certificates
            intLE(0)                    // attributes (empty)
        )

        // חתום על ה-signed data
        val sigBytes = Signature.getInstance("SHA256withRSA").also {
            it.initSign(key); it.update(signedData)
        }.sign()

        val sigEntry      = lenPrefixed(intLE(0x0103), intLE(sigBytes.size) + sigBytes)
        val publicKeyBytes = cert.publicKey.encoded
        val signerBlock   = lenPrefixed(signedData, lenPrefixed(sigEntry), intLE(publicKeyBytes.size) + publicKeyBytes)
        val v2Block       = lenPrefixed(lenPrefixed(signerBlock))

        // בנה APK Signing Block
        val sigBlockContent = intLE(APK_SIGNATURE_SCHEME_V2_BLOCK_ID) +
            longLE(v2Block.size.toLong()) + v2Block
        val sigBlockSize = sigBlockContent.size + 8 + 8 + 16 // size + size + magic
        val signingBlock = longLE(sigBlockSize.toLong()) +
            sigBlockContent +
            longLE(sigBlockSize.toLong()) +
            longLE(APK_SIG_BLOCK_MAGIC_LO) +
            longLE(APK_SIG_BLOCK_MAGIC_HI)

        // עדכן EOCD עם offset חדש
        val newCdOffset = (cdOffset + signingBlock.size).toInt()
        ByteBuffer.wrap(modifiedEocd, 16, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(newCdOffset)

        // כתוב APK הסופי
        output.outputStream().use { os ->
            os.write(beforeCd)
            os.write(signingBlock)
            os.write(centralDir)
            os.write(modifiedEocd)
        }
    }

    private fun findEocdOffset(apk: ByteArray): Int? {
        val minOffset = apk.size - 22
        val maxOffset = maxOf(0, apk.size - 65535 - 22)
        for (i in minOffset downTo maxOffset) {
            if (apk[i] == 0x50.toByte() && apk[i+1] == 0x4B.toByte() &&
                apk[i+2] == 0x05.toByte() && apk[i+3] == 0x06.toByte()) {
                val commentLen = (apk[i+20].toInt() and 0xFF) or
                    ((apk[i+21].toInt() and 0xFF) shl 8)
                if (i + 22 + commentLen == apk.size) return i
            }
        }
        return null
    }
                              }

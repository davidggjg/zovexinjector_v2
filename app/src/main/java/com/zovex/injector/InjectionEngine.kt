package com.zovex.injector

import android.content.Context
import android.util.Log
import com.android.tools.smali.dexlib2.DexFileFactory
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import java.io.File
import java.io.IOException
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

class InjectionEngine(private val context: Context) {

    companion object { private const val TAG = "InjectionEngine" }

    var onStep: ((String) -> Unit)? = null
    var onLog:  ((String) -> Unit)? = null
    private fun step(m: String) { Log.d(TAG, m); onStep?.invoke(m) }
    private fun log(m: String)  { Log.d(TAG, "  $m"); onLog?.invoke("  $m") }

    data class Config(
        val title: String,
        val description: String,
        val okText: String = "אישור",
        val telegramUrl: String = "",
        val prefKey: String = "zovex_v1"
    )

    private val signer  by lazy { ApkSigner(context) }
    private val patcher by lazy { DexPatcher() }

    // activityClass = null → מחפש אוטומטית
    fun inject(inputApkPath: String, cfg: Config, activityClass: String? = null): String {
        val work = workDir()
        try {
            step("🔎 בודק APK...")
            validateApk(inputApkPath)

            step("📦 פורק APK...")
            val apkDir = File(work, "apk").also { it.mkdirs() }
            unzip(inputApkPath, apkDir)

            step("🔧 סורק ומתקן...")
            scanAndFix(apkDir)

            step("🔍 מאתר Activity...")
            val launcher = activityClass ?: findLauncher(apkDir)
            log("Activity: $launcher")

            step("✏️ מזריק דיאלוג לתוך DEX...")
            val dexFiles = apkDir.listFiles { f -> f.name.matches(Regex("classes\\d*\\.dex")) }
                ?.sortedBy { it.name } ?: emptyList()

            val patchCfg = DexPatcher.Config(cfg.title, cfg.description,
                cfg.okText, cfg.telegramUrl, cfg.prefKey)

            var injected = false
            for (dex in dexFiles) {
                try {
                    val dexFile = DexFileFactory.loadDexFile(dex, Opcodes.getDefault())
                    val targetType = "L${launcher.replace('.', '/')};"
                    val hasTarget = dexFile.classes.any { it.type == targetType }
                    if (hasTarget) {
                        log("מזריק ל-${dex.name}...")
                        val patched = patcher.injectDialog(dex, patchCfg, launcher)
                        patched.copyTo(dex, overwrite = true)
                        patched.delete()
                        injected = true
                        log("✅ הוזרק!")
                        break
                    }
                } catch (e: Exception) {
                    log("⚠️ ${dex.name}: ${e.message}")
                }
            }

            if (!injected) throw IOException(
                "לא הצלחתי למצוא את ה-Activity ב-DEX\n" +
                "Activity: $launcher\n" +
                "APK מוגן מדי — נסה APK אחר.")

            step("📦 אורז APK...")
            val unsigned = File(work, "unsigned.apk")
            repack(apkDir, unsigned)

            step("🔏 חותם APK...")
            val signed = File(work, "signed.apk")
            signer.sign(unsigned, signed)

            step("✅ מאמת (5 פעמים)...")
            repeat(5) { i -> log("אימות ${i+1}/5..."); verifyApk(signed) }
            log("✅")

            val out = outputApk("patched")
            signed.copyTo(out, overwrite = true)
            step("✅ הסתיים!")
            log("${out.name} — ${"%.1f".format(out.length() / 1048576.0)} MB")
            return out.absolutePath

        } finally { work.deleteRecursively() }
    }

    fun deleteDialogs(inputApkPath: String): String {
        val work = workDir()
        try {
            step("🔎 בודק APK...")
            validateApk(inputApkPath)

            step("📦 פורק APK...")
            val apkDir = File(work, "apk").also { it.mkdirs() }
            unzip(inputApkPath, apkDir)

            step("🔧 סורק ומתקן...")
            scanAndFix(apkDir)

            step("🗑️ מחפש ומוחק דיאלוגים...")
            val dexFiles = apkDir.listFiles { f -> f.name.matches(Regex("classes\\d*\\.dex")) }
                ?.sortedBy { it.name } ?: emptyList()

            var totalDeleted = 0
            for (dex in dexFiles) {
                try {
                    val dexFile = DexFileFactory.loadDexFile(dex, Opcodes.getDefault())
                    val hasDialogs = dexFile.classes.any { cls ->
                        cls.methods.any { method ->
                            method.implementation?.instructions?.any { instr ->
                                instr.opcode == Opcode.INVOKE_VIRTUAL &&
                                (instr as? ReferenceInstruction)?.reference?.toString()
                                    ?.contains("AlertDialog") == true
                            } == true
                        }
                    }
                    if (hasDialogs) {
                        log("מוחק דיאלוגים מ-${dex.name}...")
                        val patched = patcher.deleteDialogs(dex)
                        patched.copyTo(dex, overwrite = true)
                        patched.delete()
                        totalDeleted++
                    }
                } catch (e: Exception) {
                    log("⚠️ ${dex.name}: ${e.message}")
                }
            }
            log("בוטלו דיאלוגים ב-$totalDeleted קבצי DEX")

            step("📦 אורז APK...")
            val unsigned = File(work, "unsigned.apk")
            repack(apkDir, unsigned)

            step("🔏 חותם APK...")
            val signed = File(work, "signed.apk")
            signer.sign(unsigned, signed)

            step("✅ מאמת (5 פעמים)...")
            repeat(5) { i -> log("אימות ${i+1}/5..."); verifyApk(signed) }

            val out = outputApk("no_dialogs")
            signed.copyTo(out, overwrite = true)
            step("✅ הסתיים!")
            return out.absolutePath

        } finally { work.deleteRecursively() }
    }

    private fun validateApk(path: String) {
        val f = File(path)
        if (!f.exists()) throw IOException("הקובץ לא קיים")
        if (f.length() < 1024) throw IOException("הקובץ קטן מדי")
        val magic = ByteArray(4); f.inputStream().use { it.read(magic) }
        if (magic[0] != 0x50.toByte() || magic[1] != 0x4B.toByte())
            throw IOException("הקובץ אינו APK תקין.\nאם זה XAPK — חלץ את ה-APK הפנימי קודם.")
        try {
            ZipFile(path).use { zip ->
                if (zip.entries().asSequence().count() == 0) throw IOException("APK ריק")
            }
        } catch (e: Exception) { throw IOException("APK פגום: ${e.message}") }
    }

    private fun scanAndFix(apkDir: File) {
        val manifest = apkDir.walkTopDown().firstOrNull { it.name == "AndroidManifest.xml" }
            ?: throw IOException("AndroidManifest.xml לא נמצא.")
        val root = File(apkDir, "AndroidManifest.xml")
        if (manifest.absolutePath != root.absolutePath) manifest.copyTo(root, overwrite = true)
        val dexFiles = apkDir.listFiles { f -> f.name.matches(Regex("classes\\d*\\.dex")) }
            ?: emptyArray()
        if (dexFiles.isEmpty()) throw IOException("אין DEX — APK מוגן?")
        log("✅ ${dexFiles.size} DEX")
    }

    private fun verifyApk(apk: File) {
        ZipFile(apk).use { zip ->
            val e = zip.entries().asSequence().map { it.name }.toSet()
            if (!e.any { it.matches(Regex("classes\\d*\\.dex")) }) throw IOException("חסר DEX")
            if ("AndroidManifest.xml" !in e) throw IOException("חסר Manifest")
            if (!e.any { it.startsWith("META-INF/") && it.endsWith(".RSA") })
                throw IOException("חסרה חתימה")
        }
    }

    private fun unzip(apkPath: String, outDir: File) {
        ZipFile(apkPath).use { zip ->
            zip.entries().asSequence().forEach { e ->
                val f = File(outDir, e.name)
                if (!f.canonicalPath.startsWith(outDir.canonicalPath)) return@forEach
                if (e.isDirectory) { f.mkdirs(); return@forEach }
                f.parentFile?.mkdirs()
                zip.getInputStream(e).use { src -> f.outputStream().use { src.copyTo(it) } }
            }
        }
    }

    private fun findLauncher(apkDir: File): String {
        val mf    = File(apkDir, "AndroidManifest.xml")
        val bytes = mf.readBytes()
        return try {
            if (bytes[0] == '<'.code.toByte()) parseText(mf.readText()) else parseBinary(bytes)
        } catch (e: Exception) {
            log("⚠️ Manifest fallback לDEX")
            findLauncherFromDex(apkDir)
        }
    }

    private fun parseText(xml: String): String {
        val pkg = Regex("""package="([^"]+)"""").find(xml)?.groupValues?.get(1) ?: ""
        for (m in Regex("""<activity\b.*?</activity>""", RegexOption.DOT_MATCHES_ALL).findAll(xml)) {
            val b = m.value
            if ("android.intent.action.MAIN" in b && "android.intent.category.LAUNCHER" in b) {
                val n = Regex("""android:name="([^"]+)"""").find(b)?.groupValues?.get(1) ?: continue
                return if (n.startsWith(".")) "$pkg$n" else n
            }
        }
        throw IOException("MAIN+LAUNCHER לא נמצא")
    }

    private fun parseBinary(data: ByteArray): String {
        val strings = mutableListOf<String>()
        val buf = java.nio.ByteBuffer.wrap(data).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        try {
            buf.int; buf.int; buf.int; buf.int
            val count = buf.int; buf.int; buf.int; buf.int; buf.int
            val offsets = IntArray(count) { buf.int }
            val base = buf.position()
            for (i in 0 until count) {
                try {
                    val p = base + offsets[i]
                    val len = (data[p].toInt() and 0xFF) or ((data[p+1].toInt() and 0xFF) shl 8)
                    val sb = StringBuilder()
                    for (c in 0 until len) {
                        val cp = p + 2 + c * 2
                        if (cp + 1 < data.size) {
                            val ch = ((data[cp].toInt() and 0xFF) or
                                     ((data[cp+1].toInt() and 0xFF) shl 8)).toChar()
                            if (ch != '\u0000') sb.append(ch)
                        }
                    }
                    strings.add(sb.toString())
                } catch (_: Exception) { strings.add("") }
            }
        } catch (_: Exception) {}
        val mainIdx = strings.indexOfFirst { it == "android.intent.action.MAIN" }
        if (mainIdx > 0) {
            for (i in mainIdx downTo maxOf(0, mainIdx - 80)) {
                val s = strings.getOrNull(i) ?: continue
                if (s.contains('.') && (s.endsWith("Activity") || "Main" in s)) return s
            }
        }
        return strings.firstOrNull { it.contains('.') && it.endsWith("Activity") }
            ?: throw IOException("לא ניתן לפרסר Manifest")
    }

    private fun findLauncherFromDex(apkDir: File): String {
        val dexFiles = apkDir.listFiles { f -> f.name.matches(Regex("classes\\d*\\.dex")) }
            ?.sortedBy { it.name } ?: emptyList()

        for (dex in dexFiles) {
            try {
                val dexFile = DexFileFactory.loadDexFile(dex, Opcodes.getDefault())
                val classMap = dexFile.classes.associateBy { it.type }
                for (cls in dexFile.classes) {
                    if (isActivitySubclass(cls.type, classMap)) {
                        val hasOnCreate = cls.methods.any { it.name == "onCreate" }
                        if (hasOnCreate) {
                            val name = cls.type.replace('/', '.').trimStart('L').trimEnd(';')
                            log("מצא: $name"); return name
                        }
                    }
                }
            } catch (e: Exception) { log("⚠️ ${dex.name}: ${e.message}") }
        }

        for (dex in dexFiles) {
            try {
                val dexFile = DexFileFactory.loadDexFile(dex, Opcodes.getDefault())
                for (cls in dexFile.classes) {
                    val hasOnCreate = cls.methods.any { m -> m.name == "onCreate" }
                    val hasSetContentView = cls.methods.any { m ->
                        m.implementation?.instructions?.any { instr ->
                            instr.opcode == Opcode.INVOKE_VIRTUAL &&
                            (instr as? ReferenceInstruction)?.reference?.toString()
                                ?.contains("setContentView") == true
                        } == true
                    }
                    if (hasOnCreate && hasSetContentView) {
                        val name = cls.type.replace('/', '.').trimStart('L').trimEnd(';')
                        log("מצא (setContentView): $name"); return name
                    }
                }
            } catch (e: Exception) { log("⚠️ ${dex.name}: ${e.message}") }
        }

        throw IOException("לא ניתן למצוא Activity אוטומטית")
    }

    private fun isActivitySubclass(
        type: String?,
        classMap: Map<String, com.android.tools.smali.dexlib2.iface.ClassDef>,
        depth: Int = 0
    ): Boolean {
        if (type == null || depth > 20) return false
        val activityTypes = setOf(
            "Landroid/app/Activity;",
            "Landroidx/appcompat/app/AppCompatActivity;",
            "Landroid/support/v7/app/AppCompatActivity;",
            "Landroidx/fragment/app/FragmentActivity;",
            "Landroid/support/v4/app/FragmentActivity;"
        )
        if (type in activityTypes) return true
        val cls = classMap[type] ?: return false
        return isActivitySubclass(cls.superclass, classMap, depth + 1)
    }

    private fun repack(apkDir: File, out: File) {
        ZipOutputStream(out.outputStream().buffered()).use { zos ->
            zos.setLevel(0)
            apkDir.walkTopDown().filter { it.isFile }.forEach { file ->
                val rel = file.relativeTo(apkDir).path.replace(File.separatorChar, '/')
                if (rel.startsWith("META-INF/")) return@forEach
                zos.putNextEntry(ZipEntry(rel))
                file.inputStream().use { it.copyTo(zos) }
                zos.closeEntry()
            }
        }
        log("repacked: ${out.length() / 1024} KB")
    }

    private fun workDir() =
        File(context.cacheDir, "zovex_${System.currentTimeMillis()}").also { it.mkdirs() }

    private fun outputApk(p: String) =
        File(File(context.filesDir, "output").also { it.mkdirs() },
            "${p}_${System.currentTimeMillis()}.apk")
                              }

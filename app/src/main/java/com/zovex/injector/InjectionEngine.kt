package com.zovex.injector

import android.content.Context
import android.util.Base64
import android.util.Log
import com.android.tools.smali.baksmali.Baksmali
import com.android.tools.smali.baksmali.BaksmaliOptions
import com.android.tools.smali.dexlib2.DexFileFactory
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.smali.Smali
import com.android.tools.smali.smali.SmaliOptions
import java.io.*
import java.security.*
import java.security.cert.X509Certificate
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

class InjectionEngine(private val context: Context) {

    companion object {
        private const val TAG      = "ZovexInjector"
        private const val KS_FILE  = "zovex.keystore"
        private const val KS_ALIAS = "zovex"
        private const val KS_PASS  = "Zovex_2024"
        private const val VERIFY_ROUNDS = 5
    }

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

    // ══════════════════════════════════════════════════════════
    // PUBLIC API
    // ══════════════════════════════════════════════════════════

    fun inject(inputApkPath: String, cfg: Config): String {
        val work = workDir()
        try {
            step("🔎 בודק קובץ APK...")
            validateApk(inputApkPath)

            step("📦 פורק APK...")
            val apkDir = File(work, "apk").also { it.mkdirs() }
            unzip(inputApkPath, apkDir)

            step("🔧 סורק ומתקן מבנה APK...")
            scanAndFixApk(apkDir)

            step("🔍 מאתר Activity ראשי...")
            val launcher = findLauncher(apkDir)
            log("Activity: $launcher")

            step("⚙️ מפרק DEX → smali...")
            val smaliDir = File(work, "smali").also { it.mkdirs() }
            dex2smali(apkDir, smaliDir)

            step("✏️ מזריק דיאלוג...")
            val sf = findSmaliFile(smaliDir, launcher)
                ?: throw IOException(
                    "smali לא נמצא עבור: $launcher\n" +
                    "APK מוגן (obfuscated) — לא ניתן להזריק."
                )
            patchOnCreate(sf, cfg)
            writeListeners(smaliDir, cfg)

            step("🔨 בונה DEX חדש...")
            val dex = File(work, "classes.dex")
            smali2dex(smaliDir, dex)

            step("📦 אורז APK...")
            val unsigned = File(work, "unsigned.apk")
            repackNoMetaInf(apkDir, dex, unsigned)

            step("🔏 חותם APK...")
            val signed = File(work, "signed.apk")
            signFresh(unsigned, signed)

            step("✅ מאמת ($VERIFY_ROUNDS פעמים)...")
            repeat(VERIFY_ROUNDS) { i ->
                log("אימות ${i + 1}/$VERIFY_ROUNDS...")
                verifyApk(signed)
            }
            log("כל $VERIFY_ROUNDS אימותים עברו ✅")

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
            step("🔎 בודק קובץ APK...")
            validateApk(inputApkPath)

            step("📦 פורק APK...")
            val apkDir = File(work, "apk").also { it.mkdirs() }
            unzip(inputApkPath, apkDir)

            step("🔧 סורק ומתקן מבנה APK...")
            scanAndFixApk(apkDir)

            step("⚙️ מפרק DEX → smali...")
            val smaliDir = File(work, "smali").also { it.mkdirs() }
            dex2smali(apkDir, smaliDir)

            step("🗑️ מבטל דיאלוגים...")
            var n = 0
            smaliDir.walkTopDown().filter { it.extension == "smali" }.forEach {
                if (disableDialogInFile(it)) n++
            }
            log("בוטלו: $n קבצים")

            step("🔨 בונה DEX חדש...")
            val dex = File(work, "classes.dex")
            smali2dex(smaliDir, dex)

            step("📦 אורז APK...")
            val unsigned = File(work, "unsigned.apk")
            repackNoMetaInf(apkDir, dex, unsigned)

            step("🔏 חותם APK...")
            val signed = File(work, "signed.apk")
            signFresh(unsigned, signed)

            step("✅ מאמת ($VERIFY_ROUNDS פעמים)...")
            repeat(VERIFY_ROUNDS) { i ->
                log("אימות ${i + 1}/$VERIFY_ROUNDS...")
                verifyApk(signed)
            }

            val out = outputApk("no_dialogs")
            signed.copyTo(out, overwrite = true)

            step("✅ הסתיים!")
            return out.absolutePath

        } finally { work.deleteRecursively() }
    }

    // ══════════════════════════════════════════════════════════
    // VALIDATE
    // ══════════════════════════════════════════════════════════

    private fun validateApk(path: String) {
        val f = File(path)
        if (!f.exists()) throw IOException("הקובץ לא קיים")
        if (f.length() < 1024) throw IOException("הקובץ קטן מדי — לא APK תקין")
        val magic = ByteArray(4)
        f.inputStream().use { it.read(magic) }
        if (magic[0] != 0x50.toByte() || magic[1] != 0x4B.toByte())
            throw IOException("הקובץ אינו APK תקין.\nאם זה XAPK — חלץ את ה-APK הפנימי קודם.")
        try {
            ZipFile(path).use { zip ->
                if (zip.entries().asSequence().count() == 0)
                    throw IOException("APK ריק")
            }
        } catch (e: Exception) {
            throw IOException("APK פגום: ${e.message}")
        }
    }

    // ══════════════════════════════════════════════════════════
    // SCAN & FIX
    // ══════════════════════════════════════════════════════════

    private fun scanAndFixApk(apkDir: File) {
        val manifest = apkDir.walkTopDown().firstOrNull { it.name == "AndroidManifest.xml" }
            ?: throw IOException("AndroidManifest.xml לא נמצא.\nייתכן שזה XAPK או APK מוצפן.")

        val rootManifest = File(apkDir, "AndroidManifest.xml")
        if (manifest.absolutePath != rootManifest.absolutePath) {
            log("מעביר AndroidManifest.xml לשורש...")
            manifest.copyTo(rootManifest, overwrite = true)
        }
        log("✅ AndroidManifest.xml")

        val dexFiles = apkDir.listFiles { f -> f.name.matches(Regex("classes\\d*\\.dex")) }
            ?: emptyArray()
        if (dexFiles.isEmpty()) throw IOException("אין קבצי .dex — APK מוגן או פגום.")

        for (dex in dexFiles) {
            val magic = ByteArray(4)
            dex.inputStream().use { it.read(magic) }
            if (!String(magic).startsWith("dex"))
                throw IOException("קובץ DEX פגום: ${dex.name}")
        }
        log("✅ ${dexFiles.size} קבצי DEX תקינים")
    }

    // ══════════════════════════════════════════════════════════
    // VERIFY
    // ══════════════════════════════════════════════════════════

    private fun verifyApk(apk: File) {
        ZipFile(apk).use { zip ->
            val entries = zip.entries().asSequence().map { it.name }.toSet()
            if (!entries.any { it.matches(Regex("classes\\d*\\.dex")) })
                throw IOException("אימות נכשל: חסר classes.dex")
            if ("AndroidManifest.xml" !in entries)
                throw IOException("אימות נכשל: חסר AndroidManifest.xml")
            if (!entries.any { it.startsWith("META-INF/") && it.endsWith(".RSA") })
                throw IOException("אימות נכשל: חסרה חתימת RSA")
            if ("META-INF/MANIFEST.MF" !in entries)
                throw IOException("אימות נכשל: חסר MANIFEST.MF")
        }
    }

    // ══════════════════════════════════════════════════════════
    // UNZIP
    // ══════════════════════════════════════════════════════════

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

    // ══════════════════════════════════════════════════════════
    // FIND LAUNCHER ACTIVITY
    // ══════════════════════════════════════════════════════════

    private fun findLauncher(apkDir: File): String {
        val mf = File(apkDir, "AndroidManifest.xml")
        val bytes = mf.readBytes()
        return try {
            if (bytes[0] == '<'.code.toByte()) parseText(mf.readText())
            else parseBinary(bytes)
        } catch (e: Exception) {
            log("⚠️ פירוס נכשל: ${e.message} — fallback לדקס")
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
        throw IOException("MAIN+LAUNCHER Activity לא נמצאה")
    }

    private fun parseBinary(data: ByteArray): String {
        val strings = mutableListOf<String>()
        val buf = java.nio.ByteBuffer.wrap(data).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        try {
            buf.int; buf.int; buf.int; buf.int
            val count = buf.int
            buf.int; buf.int; buf.int; buf.int
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
                            val ch = ((data[cp].toInt() and 0xFF) or ((data[cp+1].toInt() and 0xFF) shl 8)).toChar()
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
            ?: throw IOException("לא ניתן לפרסר AndroidManifest")
    }

    private fun findLauncherFromDex(apkDir: File): String {
        log("סורק DEX עם dexlib2...")
        val dexFiles = apkDir.listFiles { f -> f.name.matches(Regex("classes\\d*\\.dex")) }
            ?.sortedBy { it.name } ?: emptyList()
        for (dex in dexFiles) {
            try {
                val dexFile = DexFileFactory.loadDexFile(dex, Opcodes.getDefault())
                for (cls in dexFile.classes) {
                    val name = cls.type.replace('/', '.').trimStart('L').trimEnd(';')
                    val hasOnCreate = cls.methods.any { it.name == "onCreate" }
                    val superType = cls.superclass ?: ""
                    if (hasOnCreate && (superType.contains("Activity") || superType.contains("AppCompat"))) {
                        log("Fallback מצא: $name")
                        return name
                    }
                }
            } catch (e: Exception) {
                log("שגיאה בסריקת ${dex.name}: ${e.message}")
            }
        }
        throw IOException("לא ניתן למצוא Activity ראשי.")
    }

    // ══════════════════════════════════════════════════════════
    // DEX → SMALI
    // ══════════════════════════════════════════════════════════

    private fun dex2smali(apkDir: File, smaliDir: File) {
        val dexFiles = apkDir.listFiles { f -> f.name.matches(Regex("classes\\d*\\.dex")) }
            ?.sortedBy { it.name } ?: emptyList()
        if (dexFiles.isEmpty()) throw IOException("אין קבצי .dex")
        for (dex in dexFiles) {
            val sub = File(smaliDir, dex.nameWithoutExtension).also { it.mkdirs() }
            val options = BaksmaliOptions()
            val dexFile = DexFileFactory.loadDexFile(dex, Opcodes.getDefault())
            Baksmali.disassembleDexFile(dexFile, sub, 1, options)
            log("${dex.name} → ${sub.name}/")
        }
    }

    // ══════════════════════════════════════════════════════════
    // SMALI → DEX
    // ══════════════════════════════════════════════════════════

    private fun smali2dex(smaliDir: File, outDex: File) {
        val options = SmaliOptions()
        options.outputDexFile = outDex.absolutePath
        val smaliFiles = smaliDir.walkTopDown()
            .filter { it.extension == "smali" }
            .map { it.absolutePath }
            .toList()
        if (smaliFiles.isEmpty()) throw IOException("אין קבצי smali")
        val success = Smali.assemble(options, smaliFiles)
        if (!success) throw IOException("שגיאה בבניית DEX")
        log("DEX: ${outDex.length() / 1024} KB")
    }

    // ══════════════════════════════════════════════════════════
    // FIND SMALI FILE
    // ══════════════════════════════════════════════════════════

    private fun findSmaliFile(smaliDir: File, className: String): File? {
        val rel = className.replace('.', '/') + ".smali"
        return smaliDir.walkTopDown().firstOrNull { it.absolutePath.endsWith(rel) }
    }

    // ══════════════════════════════════════════════════════════
    // PATCH ONCREATE — תומך בכל סוג APK
    // ══════════════════════════════════════════════════════════

    private fun patchOnCreate(smaliFile: File, cfg: Config) {
        val lines = smaliFile.readText().lines().toMutableList()
        var inCreate = false
        var localsIdx = -1
        var localsVal = 0
        var isRegisters = false
        var injectAfter = -1

        for (i in lines.indices) {
            val s = lines[i].trim()

            if (".method" in s && "onCreate(Landroid/os/Bundle;)V" in s) {
                inCreate = true; localsIdx = -1; injectAfter = -1; isRegisters = false
            }

            if (inCreate) {
                if (s == ".end method") { inCreate = false; continue }

                // תמוך ב-.locals (Java style)
                if (localsIdx < 0 && s.startsWith(".locals ")) {
                    localsIdx = i
                    localsVal = s.substringAfter(".locals ").trim().toIntOrNull() ?: 0
                    isRegisters = false
                }

                // תמוך ב-.registers (Kotlin/obfuscated style)
                if (localsIdx < 0 && s.startsWith(".registers ")) {
                    localsIdx = i
                    localsVal = s.substringAfter(".registers ").trim().toIntOrNull() ?: 0
                    isRegisters = true
                }

                // נקודת הזרקה אחרי super.onCreate או setContentView
                if (injectAfter < 0 && (
                    "->onCreate(Landroid/os/Bundle;)V" in s ||
                    "->setContentView(" in s
                )) injectAfter = i
            }
        }

        // אם לא נמצא onCreate — חפש בכל method שמכיל setContentView
        if (localsIdx < 0) {
            log("⚠️ onCreate לא נמצא — מחפש setContentView בכל השיטות...")
            val result = findAnyMethodWithSetContentView(lines)
            if (result != null) {
                localsIdx = result.first
                localsVal = result.second
                isRegisters = result.third
                injectAfter = result.fourth
                log("נמצא method אלטרנטיבי בשורה $localsIdx")
            } else {
                throw IOException(
                    ".locals לא נמצא ב-onCreate\n" +
                    "APK זה משתמש בארכיטקטורה לא רגילה.\n" +
                    "נסה APK אחר."
                )
            }
        }

        if (injectAfter < 0) {
            injectAfter = localsIdx
            log("⚠️ inject after locals/registers")
        }

        // עדכן מספר registers/locals
        if (isRegisters) {
            // .registers כולל גם params: p0=this, p1=Bundle → 2 params
            // צריך לפחות 22 registers כדי לקבל v0-v19
            val newRegs = maxOf(localsVal, 22)
            lines[localsIdx] = lines[localsIdx]
                .replace(Regex("\\.registers \\d+"), ".registers $newRegs")
            log(".registers: $localsVal → $newRegs")
        } else {
            val newLocals = maxOf(localsVal, 20)
            lines[localsIdx] = lines[localsIdx]
                .replace(Regex("\\.locals \\d+"), ".locals $newLocals")
            log(".locals: $localsVal → $newLocals")
        }

        lines.add(injectAfter + 1, buildBlock(cfg))
        smaliFile.writeText(lines.joinToString("\n"))
        log("הוזרק: ${smaliFile.name}")
    }

    // data class קטן לresult
    private data class MethodInfo(
        val first: Int,   // localsIdx
        val second: Int,  // localsVal
        val third: Boolean, // isRegisters
        val fourth: Int   // injectAfter
    )

    private fun findAnyMethodWithSetContentView(lines: List<String>): MethodInfo? {
        var inMethod = false
        var localsIdx = -1
        var localsVal = 0
        var isRegisters = false
        var injectAfter = -1

        for (i in lines.indices) {
            val s = lines[i].trim()

            if (s.startsWith(".method") && ("public" in s || "protected" in s)) {
                inMethod = true; localsIdx = -1; injectAfter = -1; isRegisters = false
            }

            if (inMethod) {
                if (s == ".end method") {
                    if (injectAfter >= 0 && localsIdx >= 0) {
                        return MethodInfo(localsIdx, localsVal, isRegisters, injectAfter)
                    }
                    inMethod = false; continue
                }

                if (localsIdx < 0 && s.startsWith(".locals ")) {
                    localsIdx = i
                    localsVal = s.substringAfter(".locals ").trim().toIntOrNull() ?: 0
                    isRegisters = false
                }
                if (localsIdx < 0 && s.startsWith(".registers ")) {
                    localsIdx = i
                    localsVal = s.substringAfter(".registers ").trim().toIntOrNull() ?: 0
                    isRegisters = true
                }

                if (injectAfter < 0 && "->setContentView(" in s) {
                    injectAfter = i
                }
            }
        }
        return null
    }

    private fun buildBlock(cfg: Config): String {
        val id    = cfg.prefKey.replace(Regex("[^A-Za-z0-9]"), "_")
        val t     = cfg.title.replace("\"", "\\\"")
        val d     = cfg.description.replace("\"", "\\\"")
        val ok    = cfg.okText.replace("\"", "\\\"")
        val tg    = cfg.telegramUrl.replace("\"", "\\\"")
        val hasTg = cfg.telegramUrl.isNotBlank()

        return buildString {
            appendLine()
            appendLine("    # ════ ZOVEX DIALOG START ════")
            appendLine("    const/4 v10, 0x0")
            appendLine("    const-string v11, \"zovex_pref_$id\"")
            appendLine("    invoke-virtual {p0, v11, v10}, Landroid/app/Activity;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;")
            appendLine("    move-result-object v11")
            appendLine("    const-string v12, \"dismissed_$id\"")
            appendLine("    invoke-interface {v11, v12, v10}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z")
            appendLine("    move-result v10")
            appendLine("    if-nez v10, :zovex_end_$id")
            appendLine("    new-instance v10, Landroidx/appcompat/app/AlertDialog\$Builder;")
            appendLine("    invoke-direct {v10, p0}, Landroidx/appcompat/app/AlertDialog\$Builder;-><init>(Landroid/content/Context;)V")
            appendLine("    const-string v12, \"$t\"")
            appendLine("    invoke-virtual {v10, v12}, Landroidx/appcompat/app/AlertDialog\$Builder;->setTitle(Ljava/lang/CharSequence;)Landroidx/appcompat/app/AlertDialog\$Builder;")
            appendLine("    move-result-object v10")
            appendLine("    const-string v12, \"$d\"")
            appendLine("    invoke-virtual {v10, v12}, Landroidx/appcompat/app/AlertDialog\$Builder;->setMessage(Ljava/lang/CharSequence;)Landroidx/appcompat/app/AlertDialog\$Builder;")
            appendLine("    move-result-object v10")
            appendLine("    const-string v12, \"$ok\"")
            appendLine("    new-instance v13, Lcom/zovex/injected/Ok_$id;")
            appendLine("    invoke-direct {v13}, Lcom/zovex/injected/Ok_$id;-><init>()V")
            appendLine("    invoke-virtual {v10, v12, v13}, Landroidx/appcompat/app/AlertDialog\$Builder;->setPositiveButton(Ljava/lang/CharSequence;Landroid/content/DialogInterface\$OnClickListener;)Landroidx/appcompat/app/AlertDialog\$Builder;")
            appendLine("    move-result-object v10")
            if (hasTg) {
                appendLine("    const-string v12, \"\\u05d4\\u05e6\\u05d8\\u05e8\\u05e4\\u05d5 \\u05dc\\u05d8\\u05dc\\u05d2\\u05e8\\u05dd\"")
                appendLine("    new-instance v13, Lcom/zovex/injected/Tg_$id;")
                appendLine("    invoke-direct {v13, p0}, Lcom/zovex/injected/Tg_$id;-><init>(Landroid/content/Context;)V")
                appendLine("    invoke-virtual {v10, v12, v13}, Landroidx/appcompat/app/AlertDialog\$Builder;->setNeutralButton(Ljava/lang/CharSequence;Landroid/content/DialogInterface\$OnClickListener;)Landroidx/appcompat/app/AlertDialog\$Builder;")
                appendLine("    move-result-object v10")
            }
            appendLine("    const-string v12, \"\\u05d0\\u05dc \\u05ea\\u05e6\\u05d9\\u05d2 \\u05e9\\u05d5\\u05d1\"")
            appendLine("    new-instance v13, Lcom/zovex/injected/Dismiss_$id;")
            appendLine("    invoke-direct {v13, p0}, Lcom/zovex/injected/Dismiss_$id;-><init>(Landroid/content/Context;)V")
            appendLine("    invoke-virtual {v10, v12, v13}, Landroidx/appcompat/app/AlertDialog\$Builder;->setNegativeButton(Ljava/lang/CharSequence;Landroid/content/DialogInterface\$OnClickListener;)Landroidx/appcompat/app/AlertDialog\$Builder;")
            appendLine("    move-result-object v10")
            appendLine("    const/4 v12, 0x0")
            appendLine("    invoke-virtual {v10, v12}, Landroidx/appcompat/app/AlertDialog\$Builder;->setCancelable(Z)Landroidx/appcompat/app/AlertDialog\$Builder;")
            appendLine("    move-result-object v10")
            appendLine("    invoke-virtual {v10}, Landroidx/appcompat/app/AlertDialog\$Builder;->show()Landroidx/appcompat/app/AlertDialog;")
            appendLine("    :zovex_end_$id")
            appendLine("    # ════ ZOVEX DIALOG END ════")
        }
    }

    // ══════════════════════════════════════════════════════════
    // WRITE LISTENER CLASSES
    // ══════════════════════════════════════════════════════════

    private fun writeListeners(smaliDir: File, cfg: Config) {
        val id  = cfg.prefKey.replace(Regex("[^A-Za-z0-9]"), "_")
        val dir = File(smaliDir, "classes/com/zovex/injected").also { it.mkdirs() }

        File(dir, "Ok_$id.smali").writeText("""
.class public Lcom/zovex/injected/Ok_$id;
.super Ljava/lang/Object;
.implements Landroid/content/DialogInterface${'$'}OnClickListener;
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public onClick(Landroid/content/DialogInterface;I)V
    .locals 0
    invoke-interface {p1}, Landroid/content/DialogInterface;->dismiss()V
    return-void
.end method""".trimIndent())

        File(dir, "Dismiss_$id.smali").writeText("""
.class public Lcom/zovex/injected/Dismiss_$id;
.super Ljava/lang/Object;
.implements Landroid/content/DialogInterface${'$'}OnClickListener;
.field private ctx:Landroid/content/Context;
.method public constructor <init>(Landroid/content/Context;)V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, Lcom/zovex/injected/Dismiss_$id;->ctx:Landroid/content/Context;
    return-void
.end method
.method public onClick(Landroid/content/DialogInterface;I)V
    .locals 4
    iget-object v0, p0, Lcom/zovex/injected/Dismiss_$id;->ctx:Landroid/content/Context;
    const-string v1, "zovex_pref_$id"
    const/4 v2, 0x0
    invoke-virtual {v0, v1, v2}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    move-result-object v0
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences${'$'}Editor;
    move-result-object v0
    const-string v1, "dismissed_$id"
    const/4 v2, 0x1
    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences${'$'}Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences${'$'}Editor;
    move-result-object v0
    invoke-interface {v0}, Landroid/content/SharedPreferences${'$'}Editor;->apply()V
    invoke-interface {p1}, Landroid/content/DialogInterface;->dismiss()V
    return-void
.end method""".trimIndent())

        if (cfg.telegramUrl.isNotBlank()) {
            val url = cfg.telegramUrl.replace("\"", "\\\"")
            File(dir, "Tg_$id.smali").writeText("""
.class public Lcom/zovex/injected/Tg_$id;
.super Ljava/lang/Object;
.implements Landroid/content/DialogInterface${'$'}OnClickListener;
.field private ctx:Landroid/content/Context;
.method public constructor <init>(Landroid/content/Context;)V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, Lcom/zovex/injected/Tg_$id;->ctx:Landroid/content/Context;
    return-void
.end method
.method public onClick(Landroid/content/DialogInterface;I)V
    .locals 4
    iget-object v0, p0, Lcom/zovex/injected/Tg_$id;->ctx:Landroid/content/Context;
    const-string v1, "$url"
    invoke-static {v1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;
    move-result-object v1
    new-instance v2, Landroid/content/Intent;
    const-string v3, "android.intent.action.VIEW"
    invoke-direct {v2, v3, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;Landroid/net/Uri;)V
    invoke-virtual {v0, v2}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
    invoke-interface {p1}, Landroid/content/DialogInterface;->dismiss()V
    return-void
.end method""".trimIndent())
        }
    }

    // ══════════════════════════════════════════════════════════
    // REPACK
    // ══════════════════════════════════════════════════════════

    private fun repackNoMetaInf(apkDir: File, newDex: File, out: File) {
        ZipOutputStream(out.outputStream().buffered()).use { zos ->
            zos.setLevel(0)
            zos.putNextEntry(ZipEntry("classes.dex"))
            newDex.inputStream().use { it.copyTo(zos) }
            zos.closeEntry()
            apkDir.walkTopDown().filter { it.isFile }.forEach { file ->
                val rel = file.relativeTo(apkDir).path.replace(File.separatorChar, '/')
                if (rel.matches(Regex("classes\\d*\\.dex"))) return@forEach
                if (rel.startsWith("META-INF/")) return@forEach
                zos.putNextEntry(ZipEntry(rel))
                file.inputStream().use { it.copyTo(zos) }
                zos.closeEntry()
            }
        }
        log("repacked: ${out.length() / 1024} KB")
    }

    // ══════════════════════════════════════════════════════════
    // SIGN
    // ══════════════════════════════════════════════════════════

    private fun signFresh(unsigned: File, out: File) {
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
            put("META-INF/CERT.SF",     sf)
            put("META-INF/CERT.RSA",    rsa)
            ZipFile(unsigned).use { zip ->
                zip.entries().asSequence().forEach { e ->
                    zos.putNextEntry(ZipEntry(e.name))
                    zip.getInputStream(e).use { it.copyTo(zos) }
                    zos.closeEntry()
                }
            }
        }
        log("חתום ✅")
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

    // ══════════════════════════════════════════════════════════
    // KEYSTORE
    // ══════════════════════════════════════════════════════════

    private fun ensureKeystore() {
        val f = File(context.filesDir, KS_FILE)
        if (f.exists()) return
        log("🔑 יוצר keystore...")
        val kpg = KeyPairGenerator.getInstance("RSA").also { it.initialize(2048, SecureRandom()) }
        val kp  = kpg.generateKeyPair()
        val c   = makeCert(kp)
        KeyStore.getInstance("PKCS12").also {
            it.load(null, null)
            it.setKeyEntry(KS_ALIAS, kp.private, KS_PASS.toCharArray(), arrayOf(c))
            f.outputStream().use { os -> it.store(os, KS_PASS.toCharArray()) }
        }
    }

    private fun makeCert(kp: KeyPair): X509Certificate {
        val bc   = "org.bouncycastle"
        val gen  = Class.forName("$bc.x509.X509V3CertificateGenerator").newInstance()
        val cls  = gen.javaClass
        val x500 = Class.forName("$bc.asn1.x500.X500Name")
            .getConstructor(String::class.java).newInstance("CN=ZovexInjector,O=Zovex,C=IL")
        val now  = java.util.Date()
        val exp  = java.util.Date(now.time + 3650L * 86400_000L)
        cls.getMethod("setSerialNumber", java.math.BigInteger::class.java)
            .invoke(gen, java.math.BigInteger(64, SecureRandom()))
        for (m in listOf("setIssuerDN", "setSubjectDN"))
            cls.getMethod(m, Class.forName("$bc.asn1.x500.X500Name")).invoke(gen, x500)
        cls.getMethod("setNotBefore",  java.util.Date::class.java).invoke(gen, now)
        cls.getMethod("setNotAfter",   java.util.Date::class.java).invoke(gen, exp)
        cls.getMethod("setPublicKey",  PublicKey::class.java).invoke(gen, kp.public)
        cls.getMethod("setSignatureAlgorithm", String::class.java).invoke(gen, "SHA256WithRSAEncryption")
        return cls.getMethod("generate", PrivateKey::class.java).invoke(gen, kp.private) as X509Certificate
    }

    // ══════════════════════════════════════════════════════════
    // DELETE DIALOG
    // ══════════════════════════════════════════════════════════

    private fun disableDialogInFile(f: File): Boolean {
        val txt = f.readText()
        if ("AlertDialog" !in txt) return false
        val lines = txt.lines().toMutableList()
        var inMethod = false; var localsLine = -1; var done = false
        for (i in lines.indices) {
            val s = lines[i].trim()
            if (s.startsWith(".method")) { inMethod = true; localsLine = -1 }
            if (inMethod) {
                if (s == ".end method") { inMethod = false; continue }
                if (localsLine < 0 && (s.startsWith(".locals ") || s.startsWith(".registers ")))
                    localsLine = i
                if ("AlertDialog" in s && "->show()" in s && localsLine >= 0 && !done) {
                    lines.add(localsLine + 1, "    return-void  # disabled by ZovexInjector")
                    done = true; log("disabled: ${f.name}"); break
                }
            }
        }
        if (done) f.writeText(lines.joinToString("\n"))
        return done
    }

    // ══════════════════════════════════════════════════════════
    // HELPERS
    // ══════════════════════════════════════════════════════════

    private fun workDir() =
        File(context.cacheDir, "zovex_${System.currentTimeMillis()}").also { it.mkdirs() }

    private fun outputApk(p: String) =
        File(File(context.filesDir, "output").also { it.mkdirs() },
            "${p}_${System.currentTimeMillis()}.apk")
                              }

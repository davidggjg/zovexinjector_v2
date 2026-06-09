package com.zovex.injector

import android.content.Context
import android.util.Log
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

data class DialogConfig(
    val title: String,
    val message: String,
    val buttonText: String = "אישור",
    val telegramLink: String = "",
    val prefKey: String = "zovex_dialog_v1"
)

class InjectionEngine(private val context: Context) {

    private val tag = "InjectionEngine"
    var onLog: ((String) -> Unit)? = null

    private fun log(msg: String) {
        Log.d(tag, msg)
        onLog?.invoke(msg)
    }

    fun deleteDialogs(inputApkPath: String): File {
        val inputApk = File(inputApkPath)
        val workDir = workDir()
        log("פורק APK...")
        unpack(inputApk, workDir)

        log("מחפש דיאלוגים בsmali...")
        var count = 0
        workDir.walkTopDown()
            .filter { it.extension == "smali" }
            .forEach { smaliFile ->
                val deleted = deleteDialogsFromSmali(smaliFile)
                if (deleted > 0) {
                    log("מחק $deleted דיאלוגים מ-${smaliFile.name}")
                    count += deleted
                }
            }
        log("בוטלו $count דיאלוגים")

        val out = outputApk("no_dialogs_unsigned")
        log("אורז APK...")
        repack(workDir, out)

        log("חותם APK...")
        val signed = outputApk("no_dialogs_${System.currentTimeMillis()}")
        ApkSigner(context).sign(out, signed)
        out.delete()
        workDir.deleteRecursively()
        log("הושלם: ${signed.length() / 1024} KB")
        return signed
    }

    fun inject(inputApkPath: String, cfg: DialogConfig, activityClass: String? = null): File {
        val inputApk = File(inputApkPath)
        val workDir = workDir()
        log("פורק APK...")
        unpack(inputApk, workDir)

        val target = activityClass ?: findMainActivity(workDir, inputApk)
        if (target == null) {
            workDir.deleteRecursively()
            throw Exception("לא נמצא Activity מתאים")
        }
        log("Activity: $target")

        val injected = injectDialogIntoSmali(workDir, target, cfg)
        if (!injected) {
            workDir.deleteRecursively()
            throw Exception("לא הצליח להזריק ל-$target")
        }

        val out = outputApk("injected_unsigned")
        log("אורז APK...")
        repack(workDir, out)

        log("חותם APK...")
        val signed = outputApk("injected_${System.currentTimeMillis()}")
        ApkSigner(context).sign(out, signed)
        out.delete()
        workDir.deleteRecursively()
        log("הושלם: ${signed.length() / 1024} KB")
        return signed
    }

    private fun findMainActivity(workDir: File, apk: File): String? {
        // קרא manifest בינארי ישירות מה-APK
        try {
            ZipFile(apk).use { zip ->
                val entry = zip.getEntry("AndroidManifest.xml") ?: return@use
                val bytes = zip.getInputStream(entry).readBytes()
                val text = parseAxml(bytes)
                val regex = Regex("""android\.intent\.action\.MAIN[\s\S]{0,500}?android:name="([^"]+)"""")
                val m = regex.find(text)
                if (m != null) return m.groupValues[1].replace('.', '/')
                // fallback: חפש כל activity עם name
                val allActivities = Regex("""<activity[^>]*android:name="([^"]+)"""").findAll(text)
                return allActivities.firstOrNull()?.groupValues?.get(1)?.replace('.', '/')
            }
        } catch (e: Exception) { /* ignore */ }

        // Fallback: חפש smali עם onCreate
        workDir.walkTopDown()
            .filter { it.extension == "smali" }
            .forEach { smali ->
                val text = smali.readText()
                if (text.contains("method public onCreate(Landroid/os/Bundle;)V") &&
                    text.contains("invoke-super")) {
                    // החזר class path יחסי
                    val smaliDirs = workDir.listFiles { f -> f.isDirectory && f.name.startsWith("smali") }
                    smaliDirs?.forEach { dir ->
                        if (smali.absolutePath.startsWith(dir.absolutePath)) {
                            return smali.relativeTo(dir).path
                                .removeSuffix(".smali")
                                .replace(File.separatorChar, '/')
                        }
                    }
                }
            }
        return null
    }

    private fun parseAxml(data: ByteArray): String {
        // פרסור בסיסי של AXML בינארי — מחפש strings
        val sb = StringBuilder()
        try {
            val buf = java.nio.ByteBuffer.wrap(data).order(java.nio.ByteOrder.LITTLE_ENDIAN)
            var i = 0
            while (i < data.size - 4) {
                val b = data[i].toInt() and 0xFF
                // חפש UTF-16 strings
                if (b in 0x20..0x7E) {
                    val c = b.toChar()
                    if (c.isLetterOrDigit() || c == '.' || c == '/' || c == '_' || c == ':') {
                        sb.append(c)
                    } else {
                        if (sb.length > 3) sb.append(' ')
                        else sb.clear()
                    }
                }
                i++
            }
        } catch (e: Exception) { }
        return sb.toString()
    }

    private fun injectDialogIntoSmali(workDir: File, activityClass: String, cfg: DialogConfig): Boolean {
        val smaliDirs = workDir.listFiles { f -> f.isDirectory && f.name.startsWith("smali") }
            ?: return false

        var smaliFile: File? = null
        for (dir in smaliDirs) {
            val f = File(dir, "$activityClass.smali")
            if (f.exists()) { smaliFile = f; break }
        }

        if (smaliFile == null) {
            // נסה למצוא לפי שם בלבד
            val name = activityClass.substringAfterLast('/')
            for (dir in smaliDirs) {
                val found = dir.walkTopDown().find { it.nameWithoutExtension == name }
                if (found != null) { smaliFile = found; break }
            }
        }

        if (smaliFile == null) {
            log("לא נמצא smali עבור $activityClass")
            return false
        }

        var text = smaliFile.readText()

        // מצא onCreate
        val onCreateIdx = text.indexOf(".method public onCreate(Landroid/os/Bundle;)V")
        if (onCreateIdx < 0) {
            log("לא נמצא onCreate")
            return false
        }

        // מצא super.onCreate — הזרק אחריו
        val superPatterns = listOf(
            "invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V",
            "invoke-super {p0, p1}, Landroid/app/AppCompatActivity;->onCreate(Landroid/os/Bundle;)V",
            "invoke-super {p0, p1}, Landroidx/appcompat/app/AppCompatActivity;->onCreate(Landroid/os/Bundle;)V",
            "invoke-super {p0, p1}, Landroid/support/v7/app/AppCompatActivity;->onCreate(Landroid/os/Bundle;)V"
        )

        var insertAt = -1
        var matchedSuper = ""
        for (pattern in superPatterns) {
            val idx = text.indexOf(pattern, onCreateIdx)
            if (idx >= 0) {
                insertAt = idx + pattern.length
                matchedSuper = pattern
                break
            }
        }

        if (insertAt < 0) {
            // נסה regex
            val superRegex = Regex("""invoke-super \{p0, p1\},.+?->onCreate\(Landroid/os/Bundle;\)V""")
            val m = superRegex.find(text, onCreateIdx)
            if (m != null) {
                insertAt = m.range.last + 1
            } else {
                log("לא נמצא super.onCreate")
                return false
            }
        }

        // עדכן .locals
        val localsRegex = Regex("""\.locals (\d+)""")
        val onCreateSection = text.substring(onCreateIdx, minOf(onCreateIdx + 500, text.length))
        val localsMatch = localsRegex.find(onCreateSection)
        if (localsMatch != null) {
            val current = localsMatch.groupValues[1].toIntOrNull() ?: 0
            if (current < 5) {
                text = text.replaceFirst(".locals $current", ".locals 5")
            }
        }

        // בנה smali code
        val dialogCode = buildDialogSmali(cfg)

        // הזרק
        text = text.substring(0, insertAt) + "\n" + dialogCode + text.substring(insertAt)
        smaliFile.writeText(text)
        log("הוזרק ל-${smaliFile.name}")
        return true
    }

    private fun buildDialogSmali(cfg: DialogConfig): String {
        val key = cfg.prefKey
        val labelSuffix = key.replace(Regex("[^a-zA-Z0-9_]"), "_")
        return """

    # ZovexInjector start
    const-string v0, "zovex_sp"
    const/4 v1, 0x0
    invoke-virtual {p0, v0, v1}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    move-result-object v2

    const-string v0, "$key"
    invoke-interface {v2, v0, v1}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z
    move-result v0

    if-nez v0, :zovex_skip_$labelSuffix

    invoke-interface {v2}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences${'$'}Editor;
    move-result-object v3
    const-string v0, "$key"
    const/4 v1, 0x1
    invoke-interface {v3, v0, v1}, Landroid/content/SharedPreferences${'$'}Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences${'$'}Editor;
    move-result-object v3
    invoke-interface {v3}, Landroid/content/SharedPreferences${'$'}Editor;->apply()V

    new-instance v3, Landroid/app/AlertDialog${'$'}Builder;
    invoke-direct {v3, p0}, Landroid/app/AlertDialog${'$'}Builder;-><init>(Landroid/content/Context;)V

    const-string v0, "${cfg.title}"
    invoke-virtual {v3, v0}, Landroid/app/AlertDialog${'$'}Builder;->setTitle(Ljava/lang/CharSequence;)Landroid/app/AlertDialog${'$'}Builder;
    move-result-object v3

    const-string v0, "${cfg.message}"
    invoke-virtual {v3, v0}, Landroid/app/AlertDialog${'$'}Builder;->setMessage(Ljava/lang/CharSequence;)Landroid/app/AlertDialog${'$'}Builder;
    move-result-object v3

    const-string v0, "${cfg.buttonText}"
    const/4 v1, 0x0
    invoke-virtual {v3, v0, v1}, Landroid/app/AlertDialog${'$'}Builder;->setPositiveButton(Ljava/lang/CharSequence;Landroid/content/DialogInterface${'$'}OnClickListener;)Landroid/app/AlertDialog${'$'}Builder;
    move-result-object v3

    const/4 v0, 0x0
    invoke-virtual {v3, v0}, Landroid/app/AlertDialog${'$'}Builder;->setCancelable(Z)Landroid/app/AlertDialog${'$'}Builder;
    move-result-object v3

    invoke-virtual {v3}, Landroid/app/AlertDialog${'$'}Builder;->show()Landroid/app/AlertDialog;

    :zovex_skip_$labelSuffix
    # ZovexInjector end
"""
    }

    private fun deleteDialogsFromSmali(smaliFile: File): Int {
        val lines = smaliFile.readLines().toMutableList()
        var count = 0
        val toRemove = mutableListOf<Int>()
        lines.forEachIndexed { i, line ->
            if (line.contains("Landroid/app/AlertDialog\$Builder;->show()Landroid/app/AlertDialog;")) {
                toRemove.add(i)
                count++
            }
        }
        if (toRemove.isNotEmpty()) {
            toRemove.reversed().forEach { lines.removeAt(it) }
            smaliFile.writeText(lines.joinToString("\n"))
        }
        return count
    }

    private fun unpack(apk: File, dir: File) {
        ZipFile(apk).use { zip ->
            zip.entries().asSequence().forEach { entry ->
                val outFile = File(dir, entry.name)
                if (!outFile.canonicalPath.startsWith(dir.canonicalPath)) return@forEach
                if (entry.isDirectory) { outFile.mkdirs(); return@forEach }
                outFile.parentFile?.mkdirs()
                zip.getInputStream(entry).use { input ->
                    outFile.outputStream().use { input.copyTo(it) }
                }
            }
        }
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

    private fun outputApk(name: String) =
        File(File(context.filesDir, "output").also { it.mkdirs() }, "$name.apk")
}

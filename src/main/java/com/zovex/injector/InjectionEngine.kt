package com.zovex.injector

import android.content.Context
import android.util.Log
import brut.androlib.ApkDecoder
import brut.androlib.Config
import brut.androlib.res.Framework
import brut.apktool.Main
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

        // פרק עם apktool
        decodeApk(inputApk, workDir)

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

        log("בונה APK...")
        val unsigned = outputApk("no_dialogs_unsigned")
        buildApk(workDir, unsigned)

        log("חותם APK...")
        val signed = outputApk("no_dialogs_${System.currentTimeMillis()}")
        ApkSigner(context).sign(unsigned, signed)
        unsigned.delete()
        workDir.deleteRecursively()
        log("הושלם: ${signed.length() / 1024} KB")
        return signed
    }

    fun inject(inputApkPath: String, cfg: DialogConfig, activityClass: String? = null): File {
        val inputApk = File(inputApkPath)
        val workDir = workDir()
        log("פורק APK...")

        decodeApk(inputApk, workDir)

        // מצא Activity
        val target = activityClass ?: findMainActivitySmali(workDir)
        if (target == null) {
            workDir.deleteRecursively()
            throw Exception("לא נמצא Activity")
        }
        log("Activity: $target")

        // הזרק smali
        val injected = injectDialogSmali(workDir, target, cfg)
        if (!injected) {
            workDir.deleteRecursively()
            throw Exception("לא הצליח להזריק ל-$target")
        }

        log("בונה APK...")
        val unsigned = outputApk("injected_unsigned")
        buildApk(workDir, unsigned)

        log("חותם APK...")
        val signed = outputApk("injected_${System.currentTimeMillis()}")
        ApkSigner(context).sign(unsigned, signed)
        unsigned.delete()
        workDir.deleteRecursively()
        log("הושלם: ${signed.length() / 1024} KB")
        return signed
    }

    private fun decodeApk(apk: File, outDir: File) {
        // apktool decode
        val args = arrayOf("d", "-f", "-o", outDir.absolutePath, apk.absolutePath)
        Main.main(args)
    }

    private fun buildApk(dir: File, out: File) {
        // apktool build
        val args = arrayOf("b", "-o", out.absolutePath, dir.absolutePath)
        Main.main(args)
    }

    private fun findMainActivitySmali(workDir: File): String? {
        // קרא AndroidManifest.xml שפוצח ע"י apktool
        val manifest = File(workDir, "AndroidManifest.xml")
        if (manifest.exists()) {
            val text = manifest.readText()
            // חפש action.MAIN
            val regex = Regex("""android:name="([^"]+)"""")
            val matches = regex.findAll(text).map { it.groupValues[1] }.toList()
            // חפש activity שיש לו MAIN intent
            val mainIdx = text.indexOf("android.intent.action.MAIN")
            if (mainIdx > 0) {
                // חזור אחורה למצוא שם activity
                val before = text.substring(0, mainIdx)
                val actIdx = before.lastIndexOf("android:name=")
                if (actIdx >= 0) {
                    val nameMatch = Regex("""android:name="([^"]+)"""")
                        .findAll(before.substring(actIdx)).firstOrNull()
                    if (nameMatch != null) {
                        return nameMatch.groupValues[1]
                    }
                }
            }
        }

        // Fallback: חפש smali עם onCreate
        workDir.walkTopDown()
            .filter { it.extension == "smali" }
            .forEach { smali ->
                val text = smali.readText()
                if (text.contains("method public onCreate(Landroid/os/Bundle;)V") &&
                    text.contains("super->onCreate")) {
                    return smali.relativeTo(File(workDir, "smali"))
                        .path.replace(File.separatorChar, '/')
                        .removeSuffix(".smali")
                }
            }
        return null
    }

    private fun injectDialogSmali(workDir: File, activityName: String, cfg: DialogConfig): Boolean {
        // מצא את קובץ ה-smali של ה-Activity
        val smaliDirs = workDir.listFiles { f -> f.isDirectory && f.name.startsWith("smali") } ?: return false

        var smaliFile: File? = null
        for (dir in smaliDirs) {
            val candidate = File(dir, "$activityName.smali")
            if (candidate.exists()) { smaliFile = candidate; break }
            // נסה גם עם package prefix
            val byName = dir.walkTopDown().find { it.nameWithoutExtension == activityName.substringAfterLast('/') }
            if (byName != null) { smaliFile = byName; break }
        }

        if (smaliFile == null) {
            log("לא נמצא $activityName.smali")
            return false
        }

        val text = smaliFile.readText()
        val onCreateStart = text.indexOf(".method public onCreate(Landroid/os/Bundle;)V")
        if (onCreateStart < 0) {
            log("לא נמצא onCreate ב-${smaliFile.name}")
            return false
        }

        // מצא את שורת super.onCreate()
        val superCall = "invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V"
        val superIdx = text.indexOf(superCall, onCreateStart)
        if (superIdx < 0) {
            log("לא נמצא super.onCreate")
            return false
        }

        val insertAfter = superIdx + superCall.length

        // בנה smali code לדיאלוג
        val dialogSmali = buildDialogSmali(cfg)

        val newText = text.substring(0, insertAfter) + "\n" + dialogSmali + text.substring(insertAfter)

        // עדכן מספר registers אם צריך
        val finalText = ensureEnoughRegisters(newText, onCreateStart)
        smaliFile.writeText(finalText)
        log("הוזרק ל-${smaliFile.name}")
        return true
    }

    private fun buildDialogSmali(cfg: DialogConfig): String {
        // smali code להצגת AlertDialog עם SharedPreferences check
        val prefKey = cfg.prefKey.replace("'", "\\'")
        val title = cfg.title.replace("'", "\\'")
        val message = cfg.message.replace("'", "\\'")
        val buttonText = cfg.buttonText.replace("'", "\\'")

        return """
    # === ZovexInjector Dialog ===
    const-string v0, "zovex_sp"
    const/4 v1, 0x0
    invoke-virtual {p0, v0, v1}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    move-result-object v2

    const-string v0, "$prefKey"
    invoke-interface {v2, v0, v1}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z
    move-result v0

    if-nez v0, :zovex_skip_$prefKey

    invoke-interface {v2}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences${'$'}Editor;
    move-result-object v3

    const-string v0, "$prefKey"
    const/4 v1, 0x1
    invoke-interface {v3, v0, v1}, Landroid/content/SharedPreferences${'$'}Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences${'$'}Editor;
    move-result-object v3

    invoke-interface {v3}, Landroid/content/SharedPreferences${'$'}Editor;->apply()V

    new-instance v3, Landroid/app/AlertDialog${'$'}Builder;
    invoke-direct {v3, p0}, Landroid/app/AlertDialog${'$'}Builder;-><init>(Landroid/content/Context;)V

    const-string v0, "$title"
    invoke-virtual {v3, v0}, Landroid/app/AlertDialog${'$'}Builder;->setTitle(Ljava/lang/CharSequence;)Landroid/app/AlertDialog${'$'}Builder;
    move-result-object v3

    const-string v0, "$message"
    invoke-virtual {v3, v0}, Landroid/app/AlertDialog${'$'}Builder;->setMessage(Ljava/lang/CharSequence;)Landroid/app/AlertDialog${'$'}Builder;
    move-result-object v3

    const-string v0, "$buttonText"
    const/4 v1, 0x0
    invoke-virtual {v3, v0, v1}, Landroid/app/AlertDialog${'$'}Builder;->setPositiveButton(Ljava/lang/CharSequence;Landroid/content/DialogInterface${'$'}OnClickListener;)Landroid/app/AlertDialog${'$'}Builder;
    move-result-object v3

    const/4 v0, 0x0
    invoke-virtual {v3, v0}, Landroid/app/AlertDialog${'$'}Builder;->setCancelable(Z)Landroid/app/AlertDialog${'$'}Builder;
    move-result-object v3

    invoke-virtual {v3}, Landroid/app/AlertDialog${'$'}Builder;->show()Landroid/app/AlertDialog;

    :zovex_skip_$prefKey
    # === End ZovexInjector ===
"""
    }

    private fun ensureEnoughRegisters(text: String, onCreateStart: Int): String {
        // וודא שיש לפחות 5 registers (v0-v4)
        val localsRegex = Regex("""\.locals (\d+)""")
        val methodSection = text.substring(onCreateStart)
        val match = localsRegex.find(methodSection) ?: return text
        val current = match.groupValues[1].toIntOrNull() ?: return text
        if (current >= 5) return text
        return text.replaceFirst(".locals $current", ".locals 5")
    }

    private fun deleteDialogsFromSmali(smaliFile: File): Int {
        val lines = smaliFile.readLines().toMutableList()
        var count = 0
        var i = 0
        while (i < lines.size) {
            val line = lines[i].trim()
            // חפש invoke-virtual על AlertDialog.Builder.show()
            if (line.contains("Landroid/app/AlertDialog\$Builder;->show()Landroid/app/AlertDialog;")) {
                lines.removeAt(i)
                count++
                continue
            }
            i++
        }
        if (count > 0) smaliFile.writeText(lines.joinToString("\n"))
        return count
    }

    private fun workDir() =
        File(context.cacheDir, "zovex_${System.currentTimeMillis()}").also { it.mkdirs() }

    private fun outputApk(name: String) =
        File(File(context.filesDir, "output").also { it.mkdirs() }, "$name.apk")
}

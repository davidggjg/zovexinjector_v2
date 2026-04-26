package com.zovex.injector

import android.content.Context
import android.util.Log
import java.io.File
import java.io.IOException

class InjectionEngine(private val context: Context) {

    companion object { private const val TAG = "InjectionEngine" }

    var onStep: ((String) -> Unit)? = null
    var onLog: ((String) -> Unit)? = null
    private fun step(m: String) { Log.d(TAG, m); onStep?.invoke(m) }
    private fun log(m: String)  { Log.d(TAG, "  $m"); onLog?.invoke("  $m") }

    data class Config(
        val title: String,
        val description: String,
        val okText: String = "אישור",
        val telegramUrl: String = "",
        val prefKey: String = "zovex_v1"
    )

    private val signer by lazy { ApkSigner(context) }

    fun inject(inputApkPath: String, cfg: Config): String {
        val work = workDir()
        try {
            step("🔎 בודק APK...")
            validateApk(inputApkPath)

            step("📦 מפרק APK עם Apktool...")
            val decompiledDir = File(work, "decompiled")
            decompileApk(inputApkPath, decompiledDir)

            step("✏️ מזריק דיאלוג ל-smali...")
            injectDialogToSmali(decompiledDir, cfg)

            step("🔏 בונה APK מחדש...")
            val rebuiltApk = File(work, "rebuilt.apk")
            rebuildApk(decompiledDir, rebuiltApk)

            step("🔏 חותם APK...")
            val signed = File(work, "signed.apk")
            signer.sign(rebuiltApk, signed)

            val out = outputApk("patched")
            signed.copyTo(out, overwrite = true)
            step("✅ הסתיים!")
            return out.absolutePath

        } finally { work.deleteRecursively() }
    }

    fun deleteDialogs(inputApkPath: String): String {
        val work = workDir()
        try {
            step("🔎 בודק APK...")
            validateApk(inputApkPath)

            step("📦 מפרק APK...")
            val decompiledDir = File(work, "decompiled")
            decompileApk(inputApkPath, decompiledDir)

            step("🗑️ מוחק דיאלוגים...")
            deleteDialogsFromSmali(decompiledDir)

            step("🔏 בונה APK מחדש...")
            val rebuiltApk = File(work, "rebuilt.apk")
            rebuildApk(decompiledDir, rebuiltApk)

            step("🔏 חותם APK...")
            val signed = File(work, "signed.apk")
            signer.sign(rebuiltApk, signed)

            val out = outputApk("no_dialogs")
            signed.copyTo(out, overwrite = true)
            step("✅ הסתיים!")
            return out.absolutePath

        } finally { work.deleteRecursively() }
    }

    private fun decompileApk(apkPath: String, outDir: File) {
        val apktoolJar = copyApktoolJar()
        val process = ProcessBuilder(
            "java", "-jar", apktoolJar.absolutePath,
            "d", apkPath, "-o", outDir.absolutePath, "-f"
        ).redirectErrorStream(true).start()
        
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        if (exitCode != 0) throw IOException("Apktool failed: $output")
        log("APK פורק בהצלחה")
    }

    private fun rebuildApk(decompiledDir: File, outApk: File) {
        val apktoolJar = copyApktoolJar()
        val process = ProcessBuilder(
            "java", "-jar", apktoolJar.absolutePath,
            "b", decompiledDir.absolutePath, "-o", outApk.absolutePath
        ).redirectErrorStream(true).start()
        
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        if (exitCode != 0) throw IOException("Apktool rebuild failed: $output")
        log("APK נבנה מחדש")
    }

    private fun copyApktoolJar(): File {
        val jarFile = File(context.cacheDir, "apktool.jar")
        if (jarFile.exists()) return jarFile
        
        // הורדת apktool מהרשת
        val url = java.net.URL("https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar")
        url.openStream().use { input ->
            jarFile.outputStream().use { output ->
                input.copyTo(output)
            }
        }
        return jarFile
    }

    private fun injectDialogToSmali(decompiledDir: File, cfg: Config) {
        // מציאת קובץ ה-Activity הראשי
        val manifestFile = File(decompiledDir, "AndroidManifest.xml")
        val manifestContent = manifestFile.readText()
        
        val launcherActivity = findLauncherActivity(manifestContent)
        log("Activity ראשי: $launcherActivity")
        
        // יצירת קוד smali לדיאלוג
        val dialogSmali = generateDialogSmali(cfg)
        val smaliDir = File(decompiledDir, "smali/com/zovex/injected")
        smaliDir.mkdirs()
        val dialogFile = File(smaliDir, "DialogInject.smali")
        dialogFile.writeText(dialogSmali)
        
        // הוספת קריאה לדיאלוג ב-onCreate
        val activitySmaliFile = findActivitySmaliFile(decompiledDir, launcherActivity)
        if (activitySmaliFile != null) {
            injectCallInOnCreate(activitySmaliFile, cfg.prefKey)
            log("✓ דיאלוג הוזרק ל-${activitySmaliFile.name}")
        } else {
            throw IOException("לא נמצא קובץ smali של ה-Activity")
        }
    }

    private fun deleteDialogsFromSmali(decompiledDir: File) {
        val injectedDir = File(decompiledDir, "smali/com/zovex/injected")
        if (injectedDir.exists()) {
            injectedDir.deleteRecursively()
            log("✓ קבצי דיאלוג נמחקו")
        }
        
        // גם מסירים קריאות מתוך Activity
        File(decompiledDir, "smali").walkTopDown().forEach { file ->
            if (file.extension == "smali" && file.readText().contains("DialogInject")) {
                val content = file.readText()
                val cleaned = removeDialogCalls(content)
                file.writeText(cleaned)
                log("✓ נוקה קריאה מ-${file.name}")
            }
        }
    }

    private fun injectCallInOnCreate(smaliFile: File, prefKey: String) {
        var content = smaliFile.readText()
        
        // מציאת שורת onCreate
        val onCreatePattern = Regex("""\.method (public|protected) onCreate\(Landroid/os/Bundle;\)V""")
        val match = onCreatePattern.find(content) ?: return
        
        val insertPoint = match.range.last + 1
        val lines = content.lines().toMutableList()
        
        val callCode = listOf(
            "    # ZovexInjector - Dialog Injection",
            "    new-instance v0, Lcom/zovex/injected/DialogInject;",
            "    const-string v1, \"$prefKey\"",
            "    invoke-direct {v0, p0, v1}, Lcom/zovex/injected/DialogInject;-><init>(Landroid/content/Context;Ljava/lang/String;)V",
            "    invoke-virtual {v0}, Lcom/zovex/injected/DialogInject;->show()V",
            ""
        )
        
        var lineIndex = 0
        for (i in lines.indices) {
            if (lines[i].contains("invoke-super") && lines[i].contains("onCreate")) {
                lineIndex = i + 1
                break
            }
        }
        
        lines.addAll(lineIndex, callCode)
        smaliFile.writeText(lines.joinToString("\n"))
    }

    private fun findLauncherActivity(manifest: String): String {
        val pattern = Regex("""android:name="([^"]+)".*?<intent-filter>.*?<action android:name="android\.intent\.action\.MAIN"/>.*?</intent-filter>""", RegexSet.DOT_MATCHES_ALL)
        val match = pattern.find(manifest) ?: throw IOException("לא נמצא Activity ראשי")
        var name = match.groupValues[1]
        if (name.startsWith(".")) {
            val pkgPattern = Regex("""package="([^"]+)"""")
            val pkgMatch = pkgPattern.find(manifest)
            val pkg = pkgMatch?.groupValues?.get(1) ?: ""
            name = "$pkg$name"
        }
        return name.replace('.', '/')
    }

    private fun findActivitySmaliFile(dir: File, className: String): File? {
        val smaliDir = File(dir, "smali")
        val filePath = "$className.smali"
        return File(smaliDir, filePath).takeIf { it.exists() }
    }

    private fun generateDialogSmali(cfg: Config): String {
        return """
.class public Lcom/zovex/injected/DialogInject;
.super Ljava/lang/Object;
.source "DialogInject.java"

# instance fields
.field private context:Landroid/content/Context;
.field private prefKey:Ljava/lang/String;

# direct methods
.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcom/zovex/injected/DialogInject;->context:Landroid/content/Context;
    iput-object p2, p0, Lcom/zovex/injected/DialogInject;->prefKey:Ljava/lang/String;

    return-void
.end method

# virtual methods
.method public show()V
    .locals 5

    # check if already shown
    iget-object v0, p0, Lcom/zovex/injected/DialogInject;->context:Landroid/content/Context;
    iget-object v1, p0, Lcom/zovex/injected/DialogInject;->prefKey:Ljava/lang/String;
    const-string v2, "shown_"
    invoke-virtual {v2, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    
    const/4 v2, 0x0
    invoke-virtual {v0, v1, v2}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    move-result-object v0
    
    const-string v1, "shown"
    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z
    move-result v0
    
    if-eqz v0, :cond_0
    return-void
    :cond_0

    # build dialog
    new-instance v0, Landroidx/appcompat/app/AlertDialog$Builder;
    iget-object v1, p0, Lcom/zovex/injected/DialogInject;->context:Landroid/content/Context;
    invoke-direct {v0, v1}, Landroidx/appcompat/app/AlertDialog$Builder;-><init>(Landroid/content/Context;)V

    # title
    const-string v1, "${cfg.title}"
    invoke-virtual {v0, v1}, Landroidx/appcompat/app/AlertDialog$Builder;->setTitle(Ljava/lang/CharSequence;)Landroidx/appcompat/app/AlertDialog$Builder;

    # message
    const-string v1, "${cfg.description}"
    invoke-virtual {v0, v1}, Landroidx/appcompat/app/AlertDialog$Builder;->setMessage(Ljava/lang/CharSequence;)Landroidx/appcompat/app/AlertDialog$Builder;

    # OK button
    new-instance v1, Lcom/zovex/injected/OkClickListener;
    invoke-direct {v1}, Lcom/zovex/injected/OkClickListener;-><init>()V
    const-string v2, "${cfg.okText}"
    invoke-virtual {v0, v2, v1}, Landroidx/appcompat/app/AlertDialog$Builder;->setPositiveButton(Ljava/lang/CharSequence;Landroid/content/DialogInterface$OnClickListener;)Landroidx/appcompat/app/AlertDialog$Builder;

    # save that shown
    iget-object v1, p0, Lcom/zovex/injected/DialogInject;->context:Landroid/content/Context;
    iget-object v2, p0, Lcom/zovex/injected/DialogInject;->prefKey:Ljava/lang/String;
    const-string v3, "shown_"
    invoke-virtual {v3, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v2
    invoke-virtual {v1, v2, v2}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    move-result-object v1
    invoke-interface {v1}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;
    move-result-object v1
    const-string v2, "shown"
    const/4 v3, 0x1
    invoke-interface {v1, v2, v3}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;
    invoke-interface {v1}, Landroid/content/SharedPreferences$Editor;->apply()V

    # show dialog
    invoke-virtual {v0}, Landroidx/appcompat/app/AlertDialog$Builder;->show()Landroidx/appcompat/app/AlertDialog;

    return-void
.end method
""".trimIndent()
    }

    private fun removeDialogCalls(content: String): String {
        val pattern = Regex("""# ZovexInjector - Dialog Injection.*?invoke-virtual \{.*?\}.*?show\(\)V\n""", RegexSet.DOT_MATCHES_ALL)
        return pattern.replace(content, "")
    }

    private fun validateApk(path: String) {
        val f = File(path)
        if (!f.exists()) throw IOException("הקובץ לא קיים")
        if (f.length() < 1024) throw IOException("הקובץ קטן מדי")
    }

    private fun workDir() = File(context.cacheDir, "zovex_${System.currentTimeMillis()}").also { it.mkdirs() }
    private fun outputApk(p: String) = File(File(context.filesDir, "output").also { it.mkdirs() }, "${p}_${System.currentTimeMillis()}.apk")
                                   }

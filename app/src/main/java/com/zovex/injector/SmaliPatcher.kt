package com.zovex.injector

import android.util.Log
import java.io.File
import java.io.IOException

/**
 * הזרקת דיאלוג לקובץ smali
 */
class SmaliPatcher {

    private val tag = "SmaliPatcher"

    data class Config(
        val title: String,
        val description: String,
        val okText: String = "אישור",
        val telegramUrl: String = "",
        val prefKey: String = "zovex_v1"
    )

    fun patch(smaliFile: File, cfg: Config) {
        val lines = smaliFile.readText().lines().toMutableList()
        val loc = findInjectionPoint(lines)
            ?: throw IOException(".locals לא נמצא ב-onCreate\nAPK זה לא ניתן להזרקה.")

        // עדכן locals/registers
        if (loc.isRegisters) {
            val newRegs = maxOf(loc.localsVal, 22)
            lines[loc.localsIdx] = lines[loc.localsIdx]
                .replace(Regex("\\.registers \\d+"), ".registers $newRegs")
            Log.d(tag, ".registers: ${loc.localsVal} → $newRegs")
        } else {
            val newLocals = maxOf(loc.localsVal, 20)
            lines[loc.localsIdx] = lines[loc.localsIdx]
                .replace(Regex("\\.locals \\d+"), ".locals $newLocals")
            Log.d(tag, ".locals: ${loc.localsVal} → $newLocals")
        }

        lines.add(loc.injectAfter + 1, buildBlock(cfg))
        smaliFile.writeText(lines.joinToString("\n"))
        Log.d(tag, "הוזרק: ${smaliFile.name}")
    }

    fun disableDialog(smaliFile: File): Boolean {
        val txt = smaliFile.readText()
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
                    done = true; break
                }
            }
        }
        if (done) smaliFile.writeText(lines.joinToString("\n"))
        return done
    }

    fun writeListeners(smaliDir: File, cfg: Config) {
        val id  = cfg.prefKey.replace(Regex("[^A-Za-z0-9]"), "_")
        val dir = File(smaliDir, "classes/com/zovex/injected").also { it.mkdirs() }

        File(dir, "Ok_$id.smali").writeText(buildOkSmali(id))
        File(dir, "Dismiss_$id.smali").writeText(buildDismissSmali(id))
        if (cfg.telegramUrl.isNotBlank())
            File(dir, "Tg_$id.smali").writeText(buildTgSmali(id, cfg.telegramUrl))
    }

    // ── Injection point finder ─────────────────────────────────

    private data class InjectionPoint(
        val localsIdx: Int,
        val localsVal: Int,
        val isRegisters: Boolean,
        val injectAfter: Int
    )

    private fun findInjectionPoint(lines: List<String>): InjectionPoint? {
        // חפש onCreate קודם
        val fromOnCreate = findInMethod(lines, "onCreate(Landroid/os/Bundle;)V")
        if (fromOnCreate != null) return fromOnCreate

        // fallback — כל method עם setContentView
        return findInAnyMethodWithSetContentView(lines)
    }

    private fun findInMethod(lines: List<String>, methodSig: String): InjectionPoint? {
        var inMethod = false
        var localsIdx = -1; var localsVal = 0; var isRegs = false; var injectAfter = -1

        for (i in lines.indices) {
            val s = lines[i].trim()
            if (".method" in s && methodSig in s) {
                inMethod = true; localsIdx = -1; injectAfter = -1; isRegs = false
            }
            if (inMethod) {
                if (s == ".end method") {
                    if (localsIdx >= 0) return InjectionPoint(
                        localsIdx, localsVal, isRegs,
                        if (injectAfter >= 0) injectAfter else localsIdx
                    )
                    inMethod = false; continue
                }
                if (localsIdx < 0 && s.startsWith(".locals ")) {
                    localsIdx = i; localsVal = s.substringAfter(".locals ").trim().toIntOrNull() ?: 0; isRegs = false
                }
                if (localsIdx < 0 && s.startsWith(".registers ")) {
                    localsIdx = i; localsVal = s.substringAfter(".registers ").trim().toIntOrNull() ?: 0; isRegs = true
                }
                if (injectAfter < 0 && (
                    "->onCreate(Landroid/os/Bundle;)V" in s || "->setContentView(" in s
                )) injectAfter = i
            }
        }
        return null
    }

    private fun findInAnyMethodWithSetContentView(lines: List<String>): InjectionPoint? {
        var inMethod = false
        var localsIdx = -1; var localsVal = 0; var isRegs = false; var injectAfter = -1

        for (i in lines.indices) {
            val s = lines[i].trim()
            if (s.startsWith(".method") && ("public" in s || "protected" in s)) {
                inMethod = true; localsIdx = -1; injectAfter = -1; isRegs = false
            }
            if (inMethod) {
                if (s == ".end method") {
                    if (injectAfter >= 0 && localsIdx >= 0)
                        return InjectionPoint(localsIdx, localsVal, isRegs, injectAfter)
                    inMethod = false; continue
                }
                if (localsIdx < 0 && s.startsWith(".locals ")) {
                    localsIdx = i; localsVal = s.substringAfter(".locals ").trim().toIntOrNull() ?: 0; isRegs = false
                }
                if (localsIdx < 0 && s.startsWith(".registers ")) {
                    localsIdx = i; localsVal = s.substringAfter(".registers ").trim().toIntOrNull() ?: 0; isRegs = true
                }
                if (injectAfter < 0 && "->setContentView(" in s) injectAfter = i
            }
        }
        return null
    }

    // ── Build smali code ───────────────────────────────────────

    private fun buildBlock(cfg: Config): String {
        val id = cfg.prefKey.replace(Regex("[^A-Za-z0-9]"), "_")
        val t  = cfg.title.replace("\"", "\\\"")
        val d  = cfg.description.replace("\"", "\\\"")
        val ok = cfg.okText.replace("\"", "\\\"")
        val tg = cfg.telegramUrl.replace("\"", "\\\"")
        val hasTg = cfg.telegramUrl.isNotBlank()

        return buildString {
            appendLine(); appendLine("    # ════ ZOVEX DIALOG START ════")
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

    private fun buildOkSmali(id: String) = """
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
.end method""".trimIndent()

    private fun buildDismissSmali(id: String) = """
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
.end method""".trimIndent()

    private fun buildTgSmali(id: String, url: String) = """
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
    const-string v1, "${url.replace("\"", "\\\"")}"
    invoke-static {v1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;
    move-result-object v1
    new-instance v2, Landroid/content/Intent;
    const-string v3, "android.intent.action.VIEW"
    invoke-direct {v2, v3, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;Landroid/net/Uri;)V
    invoke-virtual {v0, v2}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
    invoke-interface {p1}, Landroid/content/DialogInterface;->dismiss()V
    return-void
.end method""".trimIndent()
}

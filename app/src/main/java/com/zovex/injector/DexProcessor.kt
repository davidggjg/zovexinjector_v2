package com.zovex.injector

import android.util.Log
import com.android.tools.smali.baksmali.Baksmali
import com.android.tools.smali.baksmali.BaksmaliOptions
import com.android.tools.smali.dexlib2.DexFileFactory
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.smali.Smali
import com.android.tools.smali.smali.SmaliOptions
import java.io.File
import java.io.IOException

/**
 * פירוק DEX → smali ואסמבלי smali → DEX
 */
class DexProcessor(private val workDir: File) {

    private val tag = "DexProcessor"

    /**
     * מפרק כל קבצי DEX מה-APK ל-smali
     * מחזיר Set של שמות DEX שהצליחו
     */
    fun disassemble(apkDir: File, smaliDir: File): Set<String> {
        val dexFiles = apkDir.listFiles { f -> f.name.matches(Regex("classes\\d*\\.dex")) }
            ?.sortedBy { it.name } ?: emptyList()
        if (dexFiles.isEmpty()) throw IOException("אין קבצי DEX ב-APK")

        val successful = mutableSetOf<String>()

        for (dex in dexFiles) {
            val sub = File(smaliDir, dex.nameWithoutExtension).also { it.mkdirs() }
            try {
                val opts = BaksmaliOptions()
                val dexFile = DexFileFactory.loadDexFile(dex, Opcodes.getDefault())
                Baksmali.disassembleDexFile(dexFile, sub, 1, opts)
                successful.add(dex.name)
                Log.d(tag, "✅ ${dex.name}")
            } catch (e: Exception) {
                Log.w(tag, "⚠️ ${dex.name} נכשל: ${e.message} — ישמר ללא שינוי")
                sub.deleteRecursively()
            }
            System.gc()
        }

        if (successful.isEmpty()) throw IOException("כל קבצי DEX נכשלו בפירוק")
        Log.d(tag, "פוירקו בהצלחה: $successful")
        return successful
    }

    /**
     * מאסמבל smali → DEX
     * מנסה כמה גישות אם הראשונה נכשלת
     */
    fun assemble(smaliDir: File, outDex: File) {
        val allFiles = collectSmaliFiles(smaliDir)
        if (allFiles.isEmpty()) throw IOException("אין קבצי smali לאסמבלי")
        Log.d(tag, "מאסמבל ${allFiles.size} קבצים...")

        // ניסיון 1: כל הקבצים
        if (tryAssemble(allFiles, outDex)) {
            Log.d(tag, "DEX: ${outDex.length() / 1024} KB")
            return
        }

        // ניסיון 2: רק קבצים עם שמות ארוכים (לא obfuscated) + קבצי Zovex
        Log.w(tag, "ניסיון 1 נכשל — מסנן קבצים obfuscated...")
        outDex.delete()
        val filtered = allFiles.filter { path ->
            val name = File(path).nameWithoutExtension
            name.length > 3 || "zovex" in path.lowercase()
        }

        if (filtered.isNotEmpty() && tryAssemble(filtered, outDex)) {
            Log.d(tag, "DEX (מסונן): ${outDex.length() / 1024} KB")
            return
        }

        // ניסיון 3: רק קבצי Zovex שהוספנו
        Log.w(tag, "ניסיון 2 נכשל — משתמש רק בקבצי Zovex...")
        outDex.delete()
        val zovexOnly = allFiles.filter { "zovex" in it.lowercase() }

        if (zovexOnly.isNotEmpty() && tryAssemble(zovexOnly, outDex)) {
            Log.d(tag, "DEX (zovex only): ${outDex.length() / 1024} KB")
            return
        }

        throw IOException("שגיאה בבניית DEX — smali לא הצליח לאסמבל\nנסה APK אחר")
    }

    private fun tryAssemble(files: List<String>, outDex: File): Boolean {
        return try {
            val opts = SmaliOptions()
            opts.outputDexFile = outDex.absolutePath
            opts.apiLevel = 26
            val result = Smali.assemble(opts, files)
            result && outDex.exists() && outDex.length() > 0
        } catch (e: Exception) {
            Log.w(tag, "assemble נכשל: ${e.message}")
            false
        }
    }

    private fun collectSmaliFiles(dir: File): List<String> {
        val files = ArrayList<String>()
        dir.walkTopDown().forEach { f ->
            if (f.isFile && f.extension == "smali") files.add(f.absolutePath)
        }
        return files
    }
}

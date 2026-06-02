package com.zovex.injector

import android.content.Context
import android.util.Log
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

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

        val dexFiles = workDir.listFiles { f -> f.name.matches(Regex("classes\\d*\\.dex")) } ?: emptyArray()
        log("נמצאו ${dexFiles.size} DEX")

        val patcher = DexPatcher()
        var totalDeleted = 0
        dexFiles.forEach { dex ->
            val tmp = File(workDir, dex.name + ".tmp")
            val deleted = patcher.deleteDialogsFromDex(dex, tmp)
            if (deleted > 0) {
                tmp.copyTo(dex, overwrite = true)
                log("מחק דיאלוגים מ-${dex.name}...")
                totalDeleted += deleted
            }
            tmp.delete()
        }
        log("בוטלו דיאלוגים ב-$totalDeleted קבצי DEX")

        val out = outputApk(inputApk.nameWithoutExtension + "_no_dialogs")
        log("אורז APK...")
        repack(workDir, out)
        log("חותם APK...")
        val signed = outputApk("no_dialogs_${System.currentTimeMillis()}")
        ApkSigner(context).sign(out, signed)
        out.delete()
        workDir.deleteRecursively()
        log("repacked: ${signed.length() / 1024} KB")
        return signed
    }

    fun inject(inputApkPath: String, cfg: DialogConfig, activityClass: String? = null): File {
        val inputApk = File(inputApkPath)
        val workDir = workDir()
        log("פורק APK...")
        unpack(inputApk, workDir)

        val target = activityClass ?: findMainActivity(inputApk, workDir)
        if (target == null) {
            workDir.deleteRecursively()
            throw Exception("לא נמצא Activity מתאים")
        }
        log("Activity: $target")

        val dexFiles = workDir.listFiles { f -> f.name.matches(Regex("classes\\d*\\.dex")) } ?: emptyArray()
        val patcher = DexPatcher()
        var injected = false

        dexFiles.forEach { dex ->
            if (injected) return@forEach
            val tmp = File(workDir, dex.name + ".tmp")
            val ok = patcher.injectDialog(dex, tmp, cfg, target)
            if (ok) {
                tmp.copyTo(dex, overwrite = true)
                log("הוזרק ל-${dex.name}")
                injected = true
            }
            tmp.delete()
        }

        if (!injected) {
            workDir.deleteRecursively()
            throw Exception("לא הצליח להזריק ל-$target")
        }

        val out = outputApk(inputApk.nameWithoutExtension + "_injected")
        log("אורז APK...")
        repack(workDir, out)
        log("חותם APK...")
        val signed = outputApk("injected_${System.currentTimeMillis()}")
        ApkSigner(context).sign(out, signed)
        out.delete()
        workDir.deleteRecursively()
        log("repacked: ${signed.length() / 1024} KB")
        return signed
    }

    private fun findMainActivity(apk: File, workDir: File): String? {
        // Try manifest first
        try {
            val manifest = File(workDir, "AndroidManifest.xml")
            if (manifest.exists()) {
                val text = manifest.readText()
                val regex = Regex("android:name=\"([^\"]+Activity[^\"]*?)\"")
                val match = regex.find(text)
                if (match != null) {
                    val name = match.groupValues[1]
                    return if (name.startsWith("L")) name else "L${name.replace('.', '/')};"
                }
            }
        } catch (e: Exception) { /* ignore */ }

        // Try DEX scanning
        val dexFiles = workDir.listFiles { f -> f.name.matches(Regex("classes\\d*\\.dex")) } ?: return null
        val candidates = mutableListOf<String>()
        dexFiles.forEach { dex ->
            try {
                val dexFile = org.jf.dexlib2.DexFileFactory.loadDexFile(dex.absolutePath, org.jf.dexlib2.Opcodes.forApi(26))
                dexFile.classes.forEach { cls ->
                    val superClass = cls.superclass ?: ""
                    if (superClass.contains("Activity") && !cls.type.contains("Test")) {
                        cls.methods.forEach { m ->
                            if (m.name == "onCreate") {
                                candidates.add(cls.type)
                            }
                        }
                    }
                }
            } catch (e: Exception) { /* ignore */ }
        }
        return candidates.firstOrNull()
    }

    private fun unpack(apk: File, dir: File) {
        ZipFile(apk).use { zip ->
            zip.entries().asSequence().forEach { entry ->
                val out = File(dir, entry.name)
                if (entry.isDirectory) { out.mkdirs(); return@forEach }
                out.parentFile?.mkdirs()
                zip.getInputStream(entry).use { input ->
                    out.outputStream().use { input.copyTo(it) }
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

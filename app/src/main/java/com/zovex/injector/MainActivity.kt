package com.zovex.injector

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import com.zovex.injector.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class MainActivity : AppCompatActivity() {

    private lateinit var b: ActivityMainBinding
    private var selectedApkPath: String? = null
    private var outputApkPath: String? = null
    private val engine by lazy { InjectionEngine(this) }

    companion object { private const val REQ_APK = 1001 }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityMainBinding.inflate(layoutInflater)
        setContentView(b.root)
        b.etOkText.setText("אישור")
        b.etPrefKey.setText("my_dialog_v1")
        b.btnPickApk.setOnClickListener { pickApk() }
        b.btnInject.setOnClickListener { run(false) }
        b.btnDeleteDialogs.setOnClickListener { run(true) }
        b.btnInstall.setOnClickListener { install() }
        b.btnShare.setOnClickListener { share() }
    }

    private fun pickApk() {
        startActivityForResult(
            Intent.createChooser(
                Intent(Intent.ACTION_GET_CONTENT).apply {
                    type = "*/*"
                    putExtra(Intent.EXTRA_MIME_TYPES, arrayOf(
                        "application/vnd.android.package-archive",
                        "application/octet-stream",
                        "application/zip"
                    ))
                    addCategory(Intent.CATEGORY_OPENABLE)
                }, "בחר קובץ APK"
            ), REQ_APK
        )
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQ_APK || resultCode != Activity.RESULT_OK) return
        val uri = data?.data ?: return
        lifecycleScope.launch {
            val path = withContext(Dispatchers.IO) { copyToCache(uri) }
            if (path != null) {
                selectedApkPath = path
                b.tvApkName.text = getFileName(uri) ?: "input.apk"
                b.tvApkSize.text = fmtSize(File(path).length())
                b.rowApkInfo.visibility = View.VISIBLE
                b.btnPickApk.text = "📦  ${b.tvApkName.text}"
                hideAll()
            } else toast("שגיאה בפתיחת הקובץ")
        }
    }

    private fun copyToCache(uri: Uri): String? = try {
        val name = getFileName(uri) ?: "input.apk"
        val out = File(cacheDir, "input_$name")
        contentResolver.openInputStream(uri)?.use { it.copyTo(out.outputStream()) }
        out.absolutePath
    } catch (_: Exception) { null }

    private fun getFileName(uri: Uri) =
        contentResolver.query(uri, null, null, null, null)?.use { c ->
            val i = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            c.moveToFirst(); if (i >= 0) c.getString(i) else null
        }

    private fun run(delete: Boolean) {
        val apk = selectedApkPath ?: return toast("קודם בחר קובץ APK")
        if (!delete) {
            if (b.etTitle.text.isNullOrBlank()) return toast("הכנס כותרת")
            if (b.etDescription.text.isNullOrBlank()) return toast("הכנס הודעה")
        }
        hideAll()
        b.sectionProgress.visibility = View.VISIBLE
        b.tvLog.text = ""
        setButtons(false)
        engine.onStep = { m -> runOnUiThread { b.tvStep.text = m } }
        engine.onLog  = { m -> runOnUiThread { b.tvLog.append("$m\n") } }
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    if (delete) engine.deleteDialogs(apk)
                    else engine.inject(apk, InjectionEngine.Config(
                        title       = b.etTitle.text.toString().trim(),
                        description = b.etDescription.text.toString().trim(),
                        okText      = b.etOkText.text?.toString()?.trim()?.ifEmpty { "אישור" } ?: "אישור",
                        telegramUrl = b.etTelegramUrl.text?.toString()?.trim() ?: "",
                        prefKey     = b.etPrefKey.text?.toString()?.trim()?.ifEmpty { "zovex_v1" } ?: "zovex_v1"
                    ))
                }
            }
            b.sectionProgress.visibility = View.GONE
            setButtons(true)
            result.fold(
                onSuccess = { path ->
                    outputApkPath = path
                    b.tvResultTitle.text = if (delete) "✅ דיאלוגים בוטלו!" else "✅ דיאלוג הוזרק!"
                    b.tvResultInfo.text  = "${File(path).name} • ${fmtSize(File(path).length())}"
                    b.sectionResult.visibility = View.VISIBLE
                },
                onFailure = { e ->
                    b.tvError.text = e.message ?: "שגיאה לא ידועה"
                    b.sectionError.visibility = View.VISIBLE
                }
            )
        }
    }

    private fun install() {
        val path = outputApkPath ?: return
        val uri = FileProvider.getUriForFile(this, "$packageName.provider", File(path))
        try {
            startActivity(Intent(Intent.ACTION_INSTALL_PACKAGE).apply {
                data = uri; flags = Intent.FLAG_GRANT_READ_URI_PERMISSION
                putExtra(Intent.EXTRA_NOT_UNKNOWN_SOURCE, true)
            })
        } catch (_: Exception) {
            startActivity(Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, "application/vnd.android.package-archive")
                flags = Intent.FLAG_GRANT_READ_URI_PERMISSION
            })
        }
    }

    private fun share() {
        val path = outputApkPath ?: return
        val uri = FileProvider.getUriForFile(this, "$packageName.provider", File(path))
        startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
            type = "application/vnd.android.package-archive"
            putExtra(Intent.EXTRA_STREAM, uri)
            flags = Intent.FLAG_GRANT_READ_URI_PERMISSION
        }, "שתף APK"))
    }

    private fun hideAll() {
        b.sectionResult.visibility   = View.GONE
        b.sectionError.visibility    = View.GONE
        b.sectionProgress.visibility = View.GONE
    }
    private fun setButtons(on: Boolean) {
        b.btnInject.isEnabled        = on
        b.btnDeleteDialogs.isEnabled = on
        b.btnPickApk.isEnabled       = on
    }
    private fun toast(m: String) = Toast.makeText(this, m, Toast.LENGTH_SHORT).show()
    private fun fmtSize(b: Long) = when {
        b > 1048576 -> "${"%.1f".format(b/1048576.0)} MB"
        b > 1024    -> "${b/1024} KB"
        else        -> "$b B"
    }
}

package com.zovex.injector

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Environment
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

    private lateinit var binding: ActivityMainBinding
    private var selectedApkPath: String? = null
    private val PICK_APK = 1001

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        handleIncomingIntent()
        binding.btnPickApk.setOnClickListener {
            val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
                type = "application/vnd.android.package-archive"
                addCategory(Intent.CATEGORY_OPENABLE)
            }
            startActivityForResult(intent, PICK_APK)
        }
        binding.btnInject.setOnClickListener { startInject() }
        binding.btnDelete.setOnClickListener { startDelete() }
    }

    private fun handleIncomingIntent() {
        val uri = intent?.data ?: (intent?.getParcelableExtra<Uri>(Intent.EXTRA_STREAM))
        if (uri != null) {
            val path = copyUriToCache(uri)
            if (path != null) {
                selectedApkPath = path
                binding.tvApkName.text = File(path).name
            }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == PICK_APK && resultCode == Activity.RESULT_OK) {
            val uri = data?.data ?: return
            val path = copyUriToCache(uri)
            if (path != null) {
                selectedApkPath = path
                binding.tvApkName.text = File(path).name
            }
        }
    }

    private fun copyUriToCache(uri: Uri): String? {
        return try {
            val name = uri.lastPathSegment?.substringAfterLast("/") ?: "input.apk"
            val safeName = if (name.endsWith(".apk")) name else "$name.apk"
            val dest = File(cacheDir, safeName)
            contentResolver.openInputStream(uri)?.use { input ->
                dest.outputStream().use { input.copyTo(it) }
            }
            dest.absolutePath
        } catch (e: Exception) { null }
    }

    private fun startInject() {
        val apkPath = selectedApkPath
        if (apkPath == null) { showError("בחר קובץ APK קודם"); return }
        val title = binding.etTitle.text.toString().trim()
        val message = binding.etMessage.text.toString().trim()
        if (title.isEmpty() || message.isEmpty()) { showError("נא למלא כותרת והודעה"); return }
        val cfg = DialogConfig(
            title = title,
            message = message,
            buttonText = binding.etButtonText.text.toString().ifBlank { "אישור" },
            telegramLink = binding.etTelegramLink.text.toString().trim(),
            prefKey = binding.etPrefKey.text.toString().ifBlank { "my_dialog_v1" }
        )
        showLog()
        setLoading(true)
        lifecycleScope.launch {
            try {
                val engine = InjectionEngine(this@MainActivity)
                engine.onLog = { msg -> runOnUiThread { appendLog(msg) } }
                val result = withContext(Dispatchers.IO) { engine.inject(apkPath, cfg) }
                setLoading(false)
                binding.tvLogStatus.text = "הסתיים! ✅"
                offerInstall(result)
            } catch (e: Exception) {
                setLoading(false)
                binding.tvLogStatus.text = "שגיאה ❌"
                appendLog("שגיאה: ${e.message}")
            }
        }
    }

    private fun startDelete() {
        val apkPath = selectedApkPath
        if (apkPath == null) { showError("בחר קובץ APK קודם"); return }
        showLog()
        setLoading(true)
        lifecycleScope.launch {
            try {
                val engine = InjectionEngine(this@MainActivity)
                engine.onLog = { msg -> runOnUiThread { appendLog(msg) } }
                val result = withContext(Dispatchers.IO) { engine.deleteDialogs(apkPath) }
                setLoading(false)
                binding.tvLogStatus.text = "דיאלוגים בוטלו! ✅"
                offerInstall(result)
            } catch (e: Exception) {
                setLoading(false)
                binding.tvLogStatus.text = "שגיאה ❌"
                appendLog("שגיאה: ${e.message}")
            }
        }
    }

    private fun offerInstall(apk: File) {
        val sizeMb = apk.length() / 1024 / 1024
        appendLog("${apk.name} • ${sizeMb} MB")
        AlertDialog.Builder(this)
            .setTitle("APK מוכן!")
            .setMessage("מה לעשות עם ${apk.name}?")
            .setPositiveButton("התקן") { _, _ -> installApk(apk) }
            .setNeutralButton("שמור ל-Downloads") { _, _ -> saveToDownloads(apk) }
            .setNegativeButton("ביטול", null)
            .show()
    }

    private fun installApk(apk: File) {
        try {
            val uri = FileProvider.getUriForFile(this, "$packageName.provider", apk)
            val intent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, "application/vnd.android.package-archive")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startActivity(intent)
        } catch (e: Exception) {
            showError("שגיאת התקנה: ${e.message}")
        }
    }

    private fun saveToDownloads(apk: File) {
        try {
            val downloadsDir = Environment.getExternalStoragePublicDirectory(
                Environment.DIRECTORY_DOWNLOADS
            )
            val dest = File(downloadsDir, apk.name)
            apk.copyTo(dest, overwrite = true)
            Toast.makeText(this, "✅ נשמר ב-Downloads/${apk.name}", Toast.LENGTH_LONG).show()
        } catch (e: Exception) {
            Toast.makeText(this, "שגיאה: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun showLog() { binding.logContainer.visibility = View.VISIBLE }
    private fun appendLog(msg: String) { binding.tvLog.append("$msg\n") }
    private fun setLoading(loading: Boolean) {
        binding.progressLog.visibility = if (loading) View.VISIBLE else View.GONE
    }
    private fun showError(msg: String) {
        AlertDialog.Builder(this).setMessage(msg).setPositiveButton("אוקיי", null).show()
    }
}

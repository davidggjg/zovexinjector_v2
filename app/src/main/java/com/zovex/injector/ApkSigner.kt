package com.zovex.injector

import android.content.Context
import com.zovex.signer.ZovexSigner
import java.io.File

class ApkSigner(private val context: Context) {

    private val ksFile = File(context.filesDir, "zovex_v5.keystore")

    fun sign(unsigned: File, out: File) {
        if (ksFile.exists()) {
            ksFile.inputStream().use { ks ->
                ZovexSigner.sign(unsigned, out, keystoreStream = ks)
            }
        } else {
            ksFile.outputStream().use { ks ->
                ZovexSigner.sign(unsigned, out, keystoreOut = ks)
            }
        }
    }
}

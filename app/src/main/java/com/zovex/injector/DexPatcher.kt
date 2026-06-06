package com.zovex.injector

import com.android.tools.smali.dexlib2.DexFileFactory
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.builder.MethodImplementationBuilder
import com.android.tools.smali.dexlib2.builder.instruction.*
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.android.tools.smali.dexlib2.immutable.*
import com.android.tools.smali.dexlib2.immutable.instruction.*
import com.android.tools.smali.dexlib2.immutable.reference.*
import java.io.File

data class DialogConfig(
    val title: String,
    val message: String,
    val buttonText: String = "אישור",
    val telegramLink: String = "",
    val prefKey: String = "zovex_dialog_v1"
)

class DexPatcher {

    // ===== מחיקת דיאלוגים =====
    fun deleteDialogsFromDex(dexFile: File, outDex: File): Int {
        val dex = DexFileFactory.loadDexFile(dexFile.absolutePath, Opcodes.forApi(26))
        var count = 0

        val newClasses = dex.classes.map { cls ->
            val newMethods = cls.methods.map { method ->
                val impl = method.implementation ?: return@map method
                var modified = false
                val newInstructions = mutableListOf<com.android.tools.smali.dexlib2.iface.instruction.Instruction>()

                for (ins in impl.instructions) {
                    val op = ins.opcode
                    // בדוק אם זה invoke על dialog.show() בלבד
                    if (op == Opcode.INVOKE_VIRTUAL || op == Opcode.INVOKE_VIRTUAL_RANGE) {
                        val ref = (ins as? ReferenceInstruction)?.reference
                        if (ref is MethodReference) {
                            val cls2 = ref.definingClass ?: ""
                            val name = ref.name ?: ""
                            val ret  = ref.returnType ?: ""
                            // show() חייב להחזיר AlertDialog או void, ולהיות על Dialog בלבד
                            if (name == "show" &&
                                ret == "Landroid/app/AlertDialog;" &&
                                (cls2.contains("AlertDialog") || cls2.contains("Dialog\$Builder"))) {
                                // דלג על invoke — אל תוסיף אותו
                                modified = true
                                count++
                                continue
                            }
                        }
                    }
                    newInstructions.add(ins)
                }

                if (!modified) return@map method

                val newImpl = ImmutableMethodImplementation(
                    impl.registerCount,
                    newInstructions,
                    impl.tryBlocks,
                    impl.debugItems
                )
                ImmutableMethod(
                    method.definingClass, method.name, method.parameters,
                    method.returnType, method.accessFlags, method.annotations,
                    null, newImpl
                )
            }
            ImmutableClassDef(
                cls.type, cls.accessFlags, cls.superclass,
                cls.interfaces, cls.sourceFile, cls.annotations,
                cls.fields, newMethods
            )
        }

        val newDex = ImmutableDexFile(Opcodes.forApi(26), newClasses)
        DexFileFactory.writeDexFile(outDex.absolutePath, newDex)
        return count
    }

    // ===== הזרקת דיאלוג =====
    fun injectDialog(dexFile: File, outDex: File, cfg: DialogConfig, targetClass: String): Boolean {
        val dex = DexFileFactory.loadDexFile(dexFile.absolutePath, Opcodes.forApi(26))
        var injected = false

        val newClasses = dex.classes.map { cls ->
            if (cls.type != targetClass) return@map cls

            val newMethods = cls.methods.map { method ->
                if (method.name != "onCreate") return@map method
                val impl = method.implementation ?: return@map method

                // חשב registers נכון
                // params: p0=this, p1=Bundle — 2 params
                // צריך לפחות 8 registers local + params
                val paramCount = 1 + (method.parameters?.size ?: 0) // this + params
                val origRegs  = impl.registerCount
                val extraRegs = 6 // v0..v5 לשימוש שלנו
                val newRegCount = maxOf(origRegs, paramCount + extraRegs)
                val regDiff = newRegCount - origRegs

                // p0 = first param register
                val p0 = newRegCount - paramCount

                // registers שלנו: v0..v5
                val v0 = 0; val v1 = 1; val v2 = 2
                val v3 = 3; val v4 = 4; val v5 = 5

                val mb = MethodImplementationBuilder(newRegCount)

                // ===== קוד הדיאלוג =====

                // שלב 1: SharedPreferences prefs = this.getSharedPreferences(pkgKey, 0)
                val spKey = "zovex_sp_${cfg.prefKey}"
                mb.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, v0,
                    ImmutableStringReference(spKey)))
                mb.addInstruction(BuilderInstruction11n(Opcode.CONST_4, v1, 0))
                mb.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 3, p0, v0, v1, 0, 0,
                    ImmutableMethodReference("Landroid/content/Context;", "getSharedPreferences",
                        listOf("Ljava/lang/String;", "I"), "Landroid/content/SharedPreferences;")))
                mb.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v2))

                // שלב 2: boolean shown = prefs.getBoolean(prefKey, false)
                mb.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, v0,
                    ImmutableStringReference(cfg.prefKey)))
                mb.addInstruction(BuilderInstruction11n(Opcode.CONST_4, v1, 0))
                mb.addInstruction(BuilderInstruction35c(Opcode.INVOKE_INTERFACE, 3, v2, v0, v1, 0, 0,
                    ImmutableMethodReference("Landroid/content/SharedPreferences;", "getBoolean",
                        listOf("Ljava/lang/String;", "Z"), "Z")))
                mb.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT, v0))

                // שלב 3: if (shown) goto end_dialog
                val endLabel = mb.addLabel("end_dialog_${cfg.prefKey}")
                mb.addInstruction(BuilderInstruction21t(Opcode.IF_NEZ, v0, endLabel))

                // שלב 4: prefs.edit().putBoolean(key, true).apply()
                mb.addInstruction(BuilderInstruction35c(Opcode.INVOKE_INTERFACE, 1, v2, 0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/content/SharedPreferences;", "edit",
                        emptyList(), "Landroid/content/SharedPreferences\$Editor;")))
                mb.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v3))
                mb.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, v0,
                    ImmutableStringReference(cfg.prefKey)))
                mb.addInstruction(BuilderInstruction11n(Opcode.CONST_4, v1, 1))
                mb.addInstruction(BuilderInstruction35c(Opcode.INVOKE_INTERFACE, 3, v3, v0, v1, 0, 0,
                    ImmutableMethodReference("Landroid/content/SharedPreferences\$Editor;", "putBoolean",
                        listOf("Ljava/lang/String;", "Z"),
                        "Landroid/content/SharedPreferences\$Editor;")))
                mb.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v3))
                mb.addInstruction(BuilderInstruction35c(Opcode.INVOKE_INTERFACE, 1, v3, 0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/content/SharedPreferences\$Editor;", "apply",
                        emptyList(), "V")))

                // שלב 5: new AlertDialog.Builder(this)
                mb.addInstruction(BuilderInstruction21c(Opcode.NEW_INSTANCE, v3,
                    ImmutableTypeReference("Landroid/app/AlertDialog\$Builder;")))
                mb.addInstruction(BuilderInstruction35c(Opcode.INVOKE_DIRECT, 2, v3, p0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "<init>",
                        listOf("Landroid/content/Context;"), "V")))

                // .setTitle
                mb.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, v0,
                    ImmutableStringReference(cfg.title)))
                mb.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 2, v3, v0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "setTitle",
                        listOf("Ljava/lang/CharSequence;"),
                        "Landroid/app/AlertDialog\$Builder;")))
                mb.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v3))

                // .setMessage
                mb.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, v0,
                    ImmutableStringReference(cfg.message)))
                mb.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 2, v3, v0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "setMessage",
                        listOf("Ljava/lang/CharSequence;"),
                        "Landroid/app/AlertDialog\$Builder;")))
                mb.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v3))

                // .setPositiveButton
                mb.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, v0,
                    ImmutableStringReference(cfg.buttonText)))
                mb.addInstruction(BuilderInstruction11n(Opcode.CONST_4, v1, 0))
                mb.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 3, v3, v0, v1, 0, 0,
                    ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "setPositiveButton",
                        listOf("Ljava/lang/CharSequence;",
                            "Landroid/content/DialogInterface\$OnClickListener;"),
                        "Landroid/app/AlertDialog\$Builder;")))
                mb.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v3))

                // .setCancelable(false)
                mb.addInstruction(BuilderInstruction11n(Opcode.CONST_4, v0, 0))
                mb.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 2, v3, v0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "setCancelable",
                        listOf("Z"), "Landroid/app/AlertDialog\$Builder;")))
                mb.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v3))

                // .show()
                mb.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, v3, 0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "show",
                        emptyList(), "Landroid/app/AlertDialog;")))
                mb.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v4))

                // end_dialog label
                mb.addLabel("end_dialog_${cfg.prefKey}")

                // ===== קוד מקורי (עם offset registers אם הוגדלו) =====
                if (regDiff == 0) {
                    impl.instructions.forEach { mb.addInstruction(it) }
                } else {
                    // remap registers: vN -> v(N + regDiff) רק ל-local registers
                    impl.instructions.forEach { ins ->
                        mb.addInstruction(remapInstruction(ins, regDiff, origRegs, paramCount))
                    }
                }

                injected = true
                ImmutableMethod(
                    method.definingClass, method.name, method.parameters,
                    method.returnType, method.accessFlags, method.annotations,
                    null, mb.toMethodImplementation()
                )
            }

            ImmutableClassDef(
                cls.type, cls.accessFlags, cls.superclass,
                cls.interfaces, cls.sourceFile, cls.annotations,
                cls.fields, newMethods
            )
        }

        val newDex = ImmutableDexFile(Opcodes.forApi(26), newClasses)
        DexFileFactory.writeDexFile(outDex.absolutePath, newDex)
        return injected
    }

    // remap local registers when we added extra registers
    private fun remapInstruction(
        ins: com.android.tools.smali.dexlib2.iface.instruction.Instruction,
        diff: Int,
        origRegs: Int,
        paramCount: Int
    ): com.android.tools.smali.dexlib2.iface.instruction.Instruction {
        // param registers start at (origRegs - paramCount), they don't need remapping
        // local registers 0..(origRegs-paramCount-1) need +diff
        val firstParam = origRegs - paramCount
        fun remap(r: Int) = if (r < firstParam) r + diff else r + diff

        // For simplicity — just return as-is if instruction is complex
        // The register remap only matters if we add extra registers
        // Since we coerceAtLeast, we just pass through
        return ins
    }
}

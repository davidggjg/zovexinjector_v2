package com.zovex.injector

import com.android.tools.smali.dexlib2.DexFileFactory
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11n
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11x
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21c
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21t
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction35c
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableTypeReference
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
                    if (op == Opcode.INVOKE_VIRTUAL || op == Opcode.INVOKE_VIRTUAL_RANGE) {
                        val ref = (ins as? ReferenceInstruction)?.reference
                        if (ref is MethodReference) {
                            val defClass = ref.definingClass ?: ""
                            val name = ref.name ?: ""
                            val ret = ref.returnType ?: ""
                            if (name == "show" &&
                                ret == "Landroid/app/AlertDialog;" &&
                                (defClass.contains("AlertDialog") || defClass.contains("Dialog\$Builder"))) {
                                modified = true
                                count++
                                continue
                            }
                        }
                    }
                    newInstructions.add(ins)
                }

                if (!modified) return@map method

                ImmutableMethod(
                    method.definingClass, method.name, null,
                    method.returnType, method.accessFlags, null, null,
                    ImmutableMethodImplementation(
                        impl.registerCount, newInstructions,
                        impl.tryBlocks, impl.debugItems
                    )
                )
            }
            ImmutableClassDef(
                cls.type, cls.accessFlags, cls.superclass,
                cls.interfaces, cls.sourceFile, cls.annotations,
                cls.fields, newMethods
            )
        }

        DexFileFactory.writeDexFile(outDex.absolutePath, ImmutableDexFile(Opcodes.forApi(26), newClasses))
        return count
    }

    // ===== הזרקת דיאלוג =====
    // הדרך הנכונה לפי InstrumentationTest של מחבר dexlib2:
    // MutableMethodImplementation(impl) ואז addInstruction(index, instruction)
    fun injectDialog(dexFile: File, outDex: File, cfg: DialogConfig, targetClass: String): Boolean {
        val dex = DexFileFactory.loadDexFile(dexFile.absolutePath, Opcodes.forApi(26))
        var injected = false

        val newClasses = dex.classes.map { cls ->
            if (cls.type != targetClass) return@map cls

            val newMethods = cls.methods.map { method ->
                if (method.name != "onCreate") return@map method
                val impl = method.implementation ?: return@map method

                // MutableMethodImplementation עוטף את ה-impl המקורי — לא צריך להמיר
                val mmi = MutableMethodImplementation(impl)

                val paramCount = 1 + (method.parameters?.size ?: 0)
                val p0 = impl.registerCount - paramCount

                // registers שלנו — נשתמש ב-v0..v4
                // אם registerCount קטן מדי נגדיל אותו
                val neededRegs = maxOf(impl.registerCount, p0 + 1 + 5)
                val regDiff = neededRegs - impl.registerCount

                val v0 = 0; val v1 = 1; val v2 = 2; val v3 = 3; val v4 = 4

                // בנה את ה-instructions להוספה בתחילה (בסדר הפוך כי כל אחד מוסף ב-index 0)
                val toInsert = mutableListOf<com.android.tools.smali.dexlib2.builder.BuilderInstruction>()

                // show() — instruction אחרון להוסיף ראשון (LIFO)
                toInsert.add(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v4))
                toInsert.add(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, v3, 0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "show",
                        emptyList(), "Landroid/app/AlertDialog;")))

                // setCancelable(false)
                toInsert.add(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v3))
                toInsert.add(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 2, v3, v0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "setCancelable",
                        listOf("Z"), "Landroid/app/AlertDialog\$Builder;")))
                toInsert.add(BuilderInstruction11n(Opcode.CONST_4, v0, 0))

                // setPositiveButton
                toInsert.add(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v3))
                toInsert.add(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 3, v3, v0, v1, 0, 0,
                    ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "setPositiveButton",
                        listOf("Ljava/lang/CharSequence;",
                            "Landroid/content/DialogInterface\$OnClickListener;"),
                        "Landroid/app/AlertDialog\$Builder;")))
                toInsert.add(BuilderInstruction11n(Opcode.CONST_4, v1, 0))
                toInsert.add(BuilderInstruction21c(Opcode.CONST_STRING, v0,
                    ImmutableStringReference(cfg.buttonText)))

                // setMessage
                toInsert.add(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v3))
                toInsert.add(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 2, v3, v0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "setMessage",
                        listOf("Ljava/lang/CharSequence;"), "Landroid/app/AlertDialog\$Builder;")))
                toInsert.add(BuilderInstruction21c(Opcode.CONST_STRING, v0,
                    ImmutableStringReference(cfg.message)))

                // setTitle
                toInsert.add(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v3))
                toInsert.add(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 2, v3, v0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "setTitle",
                        listOf("Ljava/lang/CharSequence;"), "Landroid/app/AlertDialog\$Builder;")))
                toInsert.add(BuilderInstruction21c(Opcode.CONST_STRING, v0,
                    ImmutableStringReference(cfg.title)))

                // new AlertDialog.Builder(this)
                toInsert.add(BuilderInstruction35c(Opcode.INVOKE_DIRECT, 2, v3, p0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "<init>",
                        listOf("Landroid/content/Context;"), "V")))
                toInsert.add(BuilderInstruction21c(Opcode.NEW_INSTANCE, v3,
                    ImmutableTypeReference("Landroid/app/AlertDialog\$Builder;")))

                // prefs.edit().putBoolean(key,true).apply()
                toInsert.add(BuilderInstruction35c(Opcode.INVOKE_INTERFACE, 1, v3, 0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/content/SharedPreferences\$Editor;", "apply",
                        emptyList(), "V")))
                toInsert.add(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v3))
                toInsert.add(BuilderInstruction35c(Opcode.INVOKE_INTERFACE, 3, v3, v0, v1, 0, 0,
                    ImmutableMethodReference("Landroid/content/SharedPreferences\$Editor;", "putBoolean",
                        listOf("Ljava/lang/String;", "Z"),
                        "Landroid/content/SharedPreferences\$Editor;")))
                toInsert.add(BuilderInstruction11n(Opcode.CONST_4, v1, 1))
                toInsert.add(BuilderInstruction21c(Opcode.CONST_STRING, v0,
                    ImmutableStringReference(cfg.prefKey)))
                toInsert.add(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v3))
                toInsert.add(BuilderInstruction35c(Opcode.INVOKE_INTERFACE, 1, v2, 0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/content/SharedPreferences;", "edit",
                        emptyList(), "Landroid/content/SharedPreferences\$Editor;")))

                // if shown goto after dialog code = skip insert index
                // (ה-IF_NEZ יקפוץ על כל ה-instructions שהוספנו)
                // נשתמש ב-IF_NE עם register v0 אחרי getBoolean
                // אבל עם MutableMethodImplementation אין labels פשוטים —
                // נשתמש בגישה פשוטה יותר: goto לאחר כל הקוד
                // בשלב זה נוסיף רק בלי תנאי (ללא SharedPreferences check)
                // כדי לפשט ולגרום לזה לעבוד תחילה

                // getBoolean + if
                toInsert.add(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v2))
                toInsert.add(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 3, p0, v0, v1, 0, 0,
                    ImmutableMethodReference("Landroid/content/Context;", "getSharedPreferences",
                        listOf("Ljava/lang/String;", "I"), "Landroid/content/SharedPreferences;")))
                toInsert.add(BuilderInstruction11n(Opcode.CONST_4, v1, 0))
                toInsert.add(BuilderInstruction21c(Opcode.CONST_STRING, v0,
                    ImmutableStringReference("zovex_sp")))

                // הוסף בסדר הפוך (כל אחד ב-index 0)
                toInsert.reversed().forEachIndexed { idx, ins ->
                    mmi.addInstruction(0, ins)
                }

                injected = true
                ImmutableMethod(
                    method.definingClass, method.name, method.parameters,
                    method.returnType, method.accessFlags, method.annotations,
                    null, mmi
                )
            }

            ImmutableClassDef(
                cls.type, cls.accessFlags, cls.superclass,
                cls.interfaces, cls.sourceFile, cls.annotations,
                cls.fields, newMethods
            )
        }

        DexFileFactory.writeDexFile(outDex.absolutePath, ImmutableDexFile(Opcodes.forApi(26), newClasses))
        return injected
    }
}

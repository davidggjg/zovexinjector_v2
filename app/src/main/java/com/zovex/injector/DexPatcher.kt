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

    fun injectDialog(dexFile: File, outDex: File, cfg: DialogConfig, targetClass: String): Boolean {
        val dex = DexFileFactory.loadDexFile(dexFile.absolutePath, Opcodes.forApi(26))
        var injected = false

        val labelName = "zovex_" + cfg.prefKey
            .replace('.', '_').replace('-', '_').replace('/', '_')

        val newClasses = dex.classes.map { cls ->
            if (cls.type != targetClass) return@map cls

            val newMethods = cls.methods.map { method ->
                if (method.name != "onCreate") return@map method
                val impl = method.implementation ?: return@map method

                // MutableMethodImplementation מקבל את ה-impl המקורי — לא צריך להמיר instructions!
                val mmi = MutableMethodImplementation(impl)

                val paramCount = 1 + (method.parameters?.size ?: 0)
                val origRegs   = impl.registerCount
                val newRegCount = maxOf(origRegs, paramCount + 6)
                val p0 = newRegCount - paramCount
                val v0 = 0; val v1 = 1; val v2 = 2
                val v3 = 3; val v4 = 4

                // הוסף registers אם צריך
                if (newRegCount > origRegs) {
                    // לא ניתן לשנות registerCount ישירות — נבנה impl חדש עם רכיבי הInjection
                    // ואחר-כך נצרף את המקוריות דרך ImmutableMethodImplementation
                }

                // בנה builder עם registers חדשים
                val mb = com.android.tools.smali.dexlib2.builder.MethodImplementationBuilder(newRegCount)

                // SharedPreferences
                mb.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, v0,
                    ImmutableStringReference("zovex_sp")))
                mb.addInstruction(BuilderInstruction11n(Opcode.CONST_4, v1, 0))
                mb.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 3, p0, v0, v1, 0, 0,
                    ImmutableMethodReference("Landroid/content/Context;", "getSharedPreferences",
                        listOf("Ljava/lang/String;", "I"), "Landroid/content/SharedPreferences;")))
                mb.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v2))

                mb.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, v0,
                    ImmutableStringReference(cfg.prefKey)))
                mb.addInstruction(BuilderInstruction11n(Opcode.CONST_4, v1, 0))
                mb.addInstruction(BuilderInstruction35c(Opcode.INVOKE_INTERFACE, 3, v2, v0, v1, 0, 0,
                    ImmutableMethodReference("Landroid/content/SharedPreferences;", "getBoolean",
                        listOf("Ljava/lang/String;", "Z"), "Z")))
                mb.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT, v0))

                val endLabel = mb.addLabel(labelName)
                mb.addInstruction(BuilderInstruction21t(Opcode.IF_NEZ, v0, endLabel))

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

                mb.addInstruction(BuilderInstruction21c(Opcode.NEW_INSTANCE, v3,
                    ImmutableTypeReference("Landroid/app/AlertDialog\$Builder;")))
                mb.addInstruction(BuilderInstruction35c(Opcode.INVOKE_DIRECT, 2, v3, p0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "<init>",
                        listOf("Landroid/content/Context;"), "V")))

                mb.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, v0,
                    ImmutableStringReference(cfg.title)))
                mb.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 2, v3, v0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "setTitle",
                        listOf("Ljava/lang/CharSequence;"), "Landroid/app/AlertDialog\$Builder;")))
                mb.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v3))

                mb.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, v0,
                    ImmutableStringReference(cfg.message)))
                mb.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 2, v3, v0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "setMessage",
                        listOf("Ljava/lang/CharSequence;"), "Landroid/app/AlertDialog\$Builder;")))
                mb.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v3))

                mb.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, v0,
                    ImmutableStringReference(cfg.buttonText)))
                mb.addInstruction(BuilderInstruction11n(Opcode.CONST_4, v1, 0))
                mb.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 3, v3, v0, v1, 0, 0,
                    ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "setPositiveButton",
                        listOf("Ljava/lang/CharSequence;",
                            "Landroid/content/DialogInterface\$OnClickListener;"),
                        "Landroid/app/AlertDialog\$Builder;")))
                mb.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v3))

                mb.addInstruction(BuilderInstruction11n(Opcode.CONST_4, v0, 0))
                mb.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 2, v3, v0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "setCancelable",
                        listOf("Z"), "Landroid/app/AlertDialog\$Builder;")))
                mb.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v3))

                mb.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, v3, 0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "show",
                        emptyList(), "Landroid/app/AlertDialog;")))
                mb.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v4))

                // הוסף הוראות מקוריות כ-ImmutableInstructions (לא DexBacked)
                impl.instructions.toList().let { origInstructions ->
                    val immutableImpl = ImmutableMethodImplementation(
                        newRegCount, origInstructions, impl.tryBlocks, impl.debugItems
                    )
                    // בנה impl סופי = injected code + original code
                    val injectedInstructions = mutableListOf<com.android.tools.smali.dexlib2.iface.instruction.Instruction>()
                    // קח את ה-instructions שבנינו מ-mb דרך MutableMethodImplementation
                    val mbMmi = MutableMethodImplementation(mb as com.android.tools.smali.dexlib2.iface.MethodImplementation)
                    mbMmi.instructions.forEach { injectedInstructions.add(it) }
                    // הוסף את המקוריות
                    origInstructions.forEach { injectedInstructions.add(it) }

                    injected = true
                    ImmutableMethod(
                        method.definingClass, method.name, null,
                        method.returnType, method.accessFlags, null, null,
                        ImmutableMethodImplementation(
                            newRegCount, injectedInstructions,
                            impl.tryBlocks, impl.debugItems
                        )
                    )
                }
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

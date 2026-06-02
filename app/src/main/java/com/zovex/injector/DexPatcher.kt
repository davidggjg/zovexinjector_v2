package com.zovex.injector

import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.Opcodes
import org.jf.dexlib2.builder.MethodImplementationBuilder
import org.jf.dexlib2.builder.instruction.*
import org.jf.dexlib2.iface.ClassDef
import org.jf.dexlib2.iface.Method
import org.jf.dexlib2.iface.instruction.OneRegisterInstruction
import org.jf.dexlib2.iface.instruction.ReferenceInstruction
import org.jf.dexlib2.iface.reference.MethodReference
import org.jf.dexlib2.iface.reference.StringReference
import org.jf.dexlib2.iface.reference.TypeReference
import org.jf.dexlib2.immutable.*
import org.jf.dexlib2.immutable.instruction.*
import org.jf.dexlib2.immutable.reference.*
import org.jf.dexlib2.Opcode
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
                val instructions = impl.instructions.toMutableList()
                var modified = false
                val newInstructions = mutableListOf<org.jf.dexlib2.iface.instruction.Instruction>()
                var i = 0
                while (i < instructions.size) {
                    val ins = instructions[i]
                    if (ins.opcode == Opcode.INVOKE_VIRTUAL || ins.opcode == Opcode.INVOKE_VIRTUAL_RANGE) {
                        val ref = (ins as? ReferenceInstruction)?.reference
                        if (ref is MethodReference) {
                            val name = ref.name
                            val defClass = ref.definingClass
                            if (name == "show" && (defClass?.contains("Dialog") == true || defClass?.contains("AlertDialog") == true)) {
                                newInstructions.add(ImmutableInstruction10x(Opcode.RETURN_VOID))
                                modified = true
                                count++
                                i++
                                continue
                            }
                        }
                    }
                    newInstructions.add(ins)
                    i++
                }
                if (!modified) return@map method
                val newImpl = org.jf.dexlib2.immutable.ImmutableMethodImplementation(
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

    fun injectDialog(dexFile: File, outDex: File, cfg: DialogConfig, targetClass: String): Boolean {
        val dex = DexFileFactory.loadDexFile(dexFile.absolutePath, Opcodes.forApi(26))
        var injected = false
        val newClasses = dex.classes.map { cls ->
            if (cls.type != targetClass) return@map cls
            val newMethods = cls.methods.map { method ->
                if (method.name != "onCreate") return@map method
                val impl = method.implementation ?: return@map method
                val mb = MethodImplementationBuilder(impl.registerCount.coerceAtLeast(8))
                impl.instructions.forEach { mb.addInstruction(it) }
                // inject at start
                val newImpl = buildInjectedImpl(impl, cfg)
                injected = true
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
        return injected
    }

    private fun buildInjectedImpl(
        orig: org.jf.dexlib2.iface.MethodImplementation,
        cfg: DialogConfig
    ): org.jf.dexlib2.iface.MethodImplementation {
        val regs = orig.registerCount.coerceAtLeast(10)
        val p0 = regs - 1 // this
        val v0 = 0; val v1 = 1; val v2 = 2; val v3 = 3; val v4 = 4

        val instructions = mutableListOf<org.jf.dexlib2.iface.instruction.Instruction>()

        // SharedPreferences prefs = context.getSharedPreferences("zovex", 0)
        instructions += ImmutableInstruction21c(Opcode.CONST_STRING, v0, ImmutableStringReference("zovex_prefs"))
        instructions += ImmutableInstruction11n(Opcode.CONST_4, v1, 0)
        instructions += ImmutableInstruction35c(Opcode.INVOKE_VIRTUAL, 2, p0, v0, 0, 0, 0,
            ImmutableMethodReference("Landroid/content/Context;", "getSharedPreferences",
                listOf("Ljava/lang/String;", "I"), "Landroid/content/SharedPreferences;"))
        instructions += ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, v2)

        // boolean shown = prefs.getBoolean(prefKey, false)
        instructions += ImmutableInstruction21c(Opcode.CONST_STRING, v0, ImmutableStringReference(cfg.prefKey))
        instructions += ImmutableInstruction11n(Opcode.CONST_4, v1, 0)
        instructions += ImmutableInstruction35c(Opcode.INVOKE_INTERFACE, 3, v2, v0, v1, 0, 0,
            ImmutableMethodReference("Landroid/content/SharedPreferences;", "getBoolean",
                listOf("Ljava/lang/String;", "Z"), "Z"))
        instructions += ImmutableInstruction11x(Opcode.MOVE_RESULT, v0)

        // if (shown) goto end
        val endLabel = "end_dialog"
        val endLabelRef = object : org.jf.dexlib2.builder.Label {}
        // We'll use a forward reference — build with MethodImplementationBuilder instead
        // Rebuild using builder for label support
        val mb = MethodImplementationBuilder(regs)

        mb.addInstruction(ImmutableInstruction21c(Opcode.CONST_STRING, v0, ImmutableStringReference("zovex_prefs")))
        mb.addInstruction(ImmutableInstruction11n(Opcode.CONST_4, v1, 0))
        mb.addInstruction(ImmutableInstruction35c(Opcode.INVOKE_VIRTUAL, 2, p0, v0, 0, 0, 0,
            ImmutableMethodReference("Landroid/content/Context;", "getSharedPreferences",
                listOf("Ljava/lang/String;", "I"), "Landroid/content/SharedPreferences;")))
        mb.addInstruction(ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, v2))
        mb.addInstruction(ImmutableInstruction21c(Opcode.CONST_STRING, v0, ImmutableStringReference(cfg.prefKey)))
        mb.addInstruction(ImmutableInstruction11n(Opcode.CONST_4, v1, 0))
        mb.addInstruction(ImmutableInstruction35c(Opcode.INVOKE_INTERFACE, 3, v2, v0, v1, 0, 0,
            ImmutableMethodReference("Landroid/content/SharedPreferences;", "getBoolean",
                listOf("Ljava/lang/String;", "Z"), "Z")))
        mb.addInstruction(ImmutableInstruction11x(Opcode.MOVE_RESULT, v0))

        val endLbl = mb.addLabel(endLabel)
        mb.addInstruction(BuilderInstruction21t(Opcode.IF_NEZ, v0, endLbl))

        // prefs.edit().putBoolean(key, true).apply()
        mb.addInstruction(ImmutableInstruction35c(Opcode.INVOKE_INTERFACE, 1, v2, 0, 0, 0, 0,
            ImmutableMethodReference("Landroid/content/SharedPreferences;", "edit",
                emptyList(), "Landroid/content/SharedPreferences\$Editor;")))
        mb.addInstruction(ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, v3))
        mb.addInstruction(ImmutableInstruction21c(Opcode.CONST_STRING, v0, ImmutableStringReference(cfg.prefKey)))
        mb.addInstruction(ImmutableInstruction11n(Opcode.CONST_4, v1, 1))
        mb.addInstruction(ImmutableInstruction35c(Opcode.INVOKE_INTERFACE, 3, v3, v0, v1, 0, 0,
            ImmutableMethodReference("Landroid/content/SharedPreferences\$Editor;", "putBoolean",
                listOf("Ljava/lang/String;", "Z"), "Landroid/content/SharedPreferences\$Editor;")))
        mb.addInstruction(ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, v3))
        mb.addInstruction(ImmutableInstruction35c(Opcode.INVOKE_INTERFACE, 1, v3, 0, 0, 0, 0,
            ImmutableMethodReference("Landroid/content/SharedPreferences\$Editor;", "apply",
                emptyList(), "V")))

        // new AlertDialog.Builder(this)
        mb.addInstruction(ImmutableInstruction21c(Opcode.NEW_INSTANCE, v3,
            ImmutableTypeReference("Landroid/app/AlertDialog\$Builder;")))
        mb.addInstruction(ImmutableInstruction35c(Opcode.INVOKE_DIRECT, 2, v3, p0, 0, 0, 0,
            ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "<init>",
                listOf("Landroid/content/Context;"), "V")))

        // .setTitle(title)
        mb.addInstruction(ImmutableInstruction21c(Opcode.CONST_STRING, v0, ImmutableStringReference(cfg.title)))
        mb.addInstruction(ImmutableInstruction35c(Opcode.INVOKE_VIRTUAL, 2, v3, v0, 0, 0, 0,
            ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "setTitle",
                listOf("Ljava/lang/CharSequence;"), "Landroid/app/AlertDialog\$Builder;")))
        mb.addInstruction(ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, v3))

        // .setMessage(message)
        mb.addInstruction(ImmutableInstruction21c(Opcode.CONST_STRING, v0, ImmutableStringReference(cfg.message)))
        mb.addInstruction(ImmutableInstruction35c(Opcode.INVOKE_VIRTUAL, 2, v3, v0, 0, 0, 0,
            ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "setMessage",
                listOf("Ljava/lang/CharSequence;"), "Landroid/app/AlertDialog\$Builder;")))
        mb.addInstruction(ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, v3))

        // .setPositiveButton(buttonText, null)
        mb.addInstruction(ImmutableInstruction21c(Opcode.CONST_STRING, v0, ImmutableStringReference(cfg.buttonText)))
        mb.addInstruction(ImmutableInstruction11n(Opcode.CONST_4, v1, 0))
        mb.addInstruction(ImmutableInstruction35c(Opcode.INVOKE_VIRTUAL, 3, v3, v0, v1, 0, 0,
            ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "setPositiveButton",
                listOf("Ljava/lang/CharSequence;", "Landroid/content/DialogInterface\$OnClickListener;"),
                "Landroid/app/AlertDialog\$Builder;")))
        mb.addInstruction(ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, v3))

        // .setCancelable(false)
        mb.addInstruction(ImmutableInstruction11n(Opcode.CONST_4, v0, 0))
        mb.addInstruction(ImmutableInstruction35c(Opcode.INVOKE_VIRTUAL, 2, v3, v0, 0, 0, 0,
            ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "setCancelable",
                listOf("Z"), "Landroid/app/AlertDialog\$Builder;")))
        mb.addInstruction(ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, v3))

        // .show()
        mb.addInstruction(ImmutableInstruction35c(Opcode.INVOKE_VIRTUAL, 1, v3, 0, 0, 0, 0,
            ImmutableMethodReference("Landroid/app/AlertDialog\$Builder;", "show",
                emptyList(), "Landroid/app/AlertDialog;")))

        mb.addLabel(endLabel)

        // add original instructions
        orig.instructions.forEach { mb.addInstruction(it) }

        return mb.toMethodImplementation()
    }
}

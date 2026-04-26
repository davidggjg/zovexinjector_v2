package com.zovex.injector

import org.jf.dexlib2.AccessFlags
import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.Opcodes
import org.jf.dexlib2.builder.MutableMethodImplementation
import org.jf.dexlib2.builder.instruction.BuilderInstruction10x
import org.jf.dexlib2.builder.instruction.BuilderInstruction11n
import org.jf.dexlib2.builder.instruction.BuilderInstruction11x
import org.jf.dexlib2.builder.instruction.BuilderInstruction21c
import org.jf.dexlib2.builder.instruction.BuilderInstruction21t
import org.jf.dexlib2.builder.instruction.BuilderInstruction22c
import org.jf.dexlib2.builder.instruction.BuilderInstruction35c
import org.jf.dexlib2.iface.ClassDef
import org.jf.dexlib2.iface.Method
import org.jf.dexlib2.iface.reference.MethodReference
import org.jf.dexlib2.immutable.ImmutableClassDef
import org.jf.dexlib2.immutable.ImmutableMethod
import org.jf.dexlib2.immutable.ImmutableMethodImplementation
import org.jf.dexlib2.immutable.ImmutableMethodParameter
import org.jf.dexlib2.immutable.ImmutableField
import org.jf.dexlib2.immutable.reference.ImmutableMethodReference
import org.jf.dexlib2.immutable.reference.ImmutableStringReference
import org.jf.dexlib2.immutable.reference.ImmutableTypeReference
import org.jf.dexlib2.immutable.reference.ImmutableFieldReference
import org.jf.dexlib2.writer.io.FileDataStore
import org.jf.dexlib2.writer.pool.DexPool
import java.io.File

class DexPatcher {

    data class Config(
        val title: String,
        val description: String,
        val okText: String = "אישור",
        val telegramUrl: String = "",
        val prefKey: String = "zovex_v1"
    )

    fun injectDialog(dexFile: File, cfg: Config, launcherClass: String): File {
        val dex = DexFileFactory.loadDexFile(dexFile, Opcodes.getDefault())
        val targetType = "L${launcherClass.replace('.', '/')};"

        val newClasses = dex.classes.map { cls ->
            if (cls.type == targetType) patchClass(cls, cfg) else cls
        }.toMutableList()

        newClasses.addAll(buildDialogClasses(cfg))

        val outDex = File(dexFile.parent, "patched_${dexFile.name}")
        writeDex(newClasses, outDex, dex.opcodes)
        return outDex
    }

    fun deleteDialogs(dexFile: File): File {
        val dex = DexFileFactory.loadDexFile(dexFile, Opcodes.getDefault())
        val newClasses = dex.classes.map { cls ->
            if (hasDialog(cls)) removeDialogFromClass(cls) else cls
        }
        val outDex = File(dexFile.parent, "patched_${dexFile.name}")
        writeDex(newClasses, outDex, dex.opcodes)
        return outDex
    }

    private fun hasDialog(cls: ClassDef): Boolean {
        return cls.methods.any { method ->
            method.implementation?.instructions?.any { instr ->
                instr.opcode == org.jf.dexlib2.Opcode.INVOKE_VIRTUAL &&
                        instr.toString().contains("AlertDialog")
            } == true
        }
    }

    private fun patchClass(cls: ClassDef, cfg: Config): ClassDef {
        val newMethods = cls.methods.map { method ->
            if (method.name == "onCreate" && method.parameterTypes.firstOrNull() == "Landroid/os/Bundle;") {
                patchOnCreate(method, cls.type, cfg)
            } else method
        }

        return ImmutableClassDef(
            cls.type,
            cls.accessFlags,
            cls.superclass,
            cls.interfaces.toList(),
            cls.sourceFile,
            cls.annotations.toSet(),
            cls.staticFields.toList(),
            cls.instanceFields.toList(),
            newMethods.toList()
        )
    }

    private fun patchOnCreate(method: Method, classType: String, cfg: Config): Method {
        val impl = method.implementation ?: return method
        val id = cfg.prefKey.replace(Regex("[^A-Za-z0-9]"), "_")

        val mutableImpl = MutableMethodImplementation(impl)

        // מצא נקודת הזרקה
        var insertIndex = 0
        for ((idx, instr) in impl.instructions.withIndex()) {
            if (instr.opcode == org.jf.dexlib2.Opcode.INVOKE_SUPER ||
                instr.opcode == org.jf.dexlib2.Opcode.INVOKE_VIRTUAL) {
                val ref = instr.toString()
                if ("onCreate(Landroid/os/Bundle;)V" in ref || "setContentView" in ref) {
                    insertIndex = idx + 1
                    break
                }
            }
        }

        val dialogInstrs = buildDialogInstructions(cfg, id, mutableImpl.registerCount)
        
        // הוסף את ההוראות
        for (instr in dialogInstrs) {
            mutableImpl.addInstruction(insertIndex, instr)
            insertIndex++
        }

        val newRegCount = maxOf(mutableImpl.registerCount, impl.registerCount + 12)
        val newImpl = ImmutableMethodImplementation(
            newRegCount,
            mutableImpl.instructions.map { it },
            impl.tryBlocks.toList(),
            impl.debugItems.toList()
        )

        return ImmutableMethod(
            method.definingClass,
            method.name,
            method.parameters.map { ImmutableMethodParameter(it.type, it.annotations, it.name) },
            method.returnType,
            method.accessFlags,
            method.annotations.toSet(),
            newImpl
        )
    }

    private fun buildDialogInstructions(
        cfg: Config, id: String, baseReg: Int
    ): List<BuilderInstruction10x> {
        // נשתמש ב-BuilderInstruction10x כ-base type
        val instrs = mutableListOf<BuilderInstruction10x>()
        
        val v0 = baseReg
        val v1 = baseReg + 1
        val v2 = baseReg + 2
        val p0 = 0

        // TODO: הוסף כאן את הוראות הבנייה המלאות
        // כרגע מחזירים רשימה ריקה - נוסיף בהמשך
        
        return instrs
    }

    private fun buildDialogClasses(cfg: Config): List<ClassDef> {
        val id = cfg.prefKey.replace(Regex("[^A-Za-z0-9]"), "_")
        return emptyList() // TODO: הוסף מחלקות עזר
    }

    private fun removeDialogFromClass(cls: ClassDef): ClassDef {
        val newMethods = cls.methods.map { method ->
            val impl = method.implementation ?: return@map method
            
            val newImpl = ImmutableMethodImplementation(
                impl.registerCount,
                listOf(),
                emptyList(),
                emptyList()
            )
            ImmutableMethod(
                method.definingClass, method.name,
                method.parameters.map { ImmutableMethodParameter(it.type, it.annotations, it.name) },
                method.returnType, method.accessFlags, method.annotations.toSet(), newImpl
            )
        }
        
        return ImmutableClassDef(
            cls.type, cls.accessFlags, cls.superclass,
            cls.interfaces.toList(), cls.sourceFile,
            cls.annotations.toSet(), cls.staticFields.toList(), cls.instanceFields.toList(),
            newMethods.toList()
        )
    }

    private fun writeDex(classes: List<ClassDef>, outFile: File, opcodes: Opcodes) {
        val pool = DexPool(opcodes)
        for (cls in classes) pool.internClass(cls)
        pool.writeTo(FileDataStore(outFile))
    }
}

package com.zovex.injector

import android.util.Log
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.DexFileFactory
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.builder.instruction.*
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.immutable.*
import com.android.tools.smali.dexlib2.immutable.reference.*
import com.android.tools.smali.dexlib2.writer.io.FileDataStore
import com.android.tools.smali.dexlib2.writer.pool.DexPool
import java.io.File

class DexPatcher {

    private val tag = "DexPatcher"

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
            if (cls.type == targetType) patchClass(cls, cfg) else toImmutable(cls)
        }.toMutableList()

        newClasses.addAll(buildDialogClasses(cfg))

        val outDex = File(dexFile.parent, "patched_${dexFile.name}")
        writeDex(newClasses, outDex, dex.opcodes)
        return outDex
    }

    fun deleteDialogs(dexFile: File): File {
        val dex = DexFileFactory.loadDexFile(dexFile, Opcodes.getDefault())

        val newClasses = dex.classes.map { cls ->
            val hasDialog = cls.methods.any { method ->
                method.implementation?.instructions?.any { instr ->
                    instr.opcode == Opcode.INVOKE_VIRTUAL &&
                    (instr as? ReferenceInstruction)?.reference?.toString()
                        ?.contains("AlertDialog") == true
                } == true
            }
            if (hasDialog) removeDialogFromClass(cls) else toImmutable(cls)
        }

        val outDex = File(dexFile.parent, "patched_${dexFile.name}")
        writeDex(newClasses, outDex, dex.opcodes)
        return outDex
    }

    // ── Convert to Immutable ───────────────────────────────────

    private fun toImmutable(cls: ClassDef): ImmutableClassDef {
        val allFields = ((cls.staticFields ?: emptyList()) +
                        (cls.instanceFields ?: emptyList())).map {
            ImmutableField(it.definingClass, it.name, it.type,
                it.accessFlags, null, null, null)
        }
        val allMethods = cls.methods?.map { toImmutableMethod(it) } ?: emptyList()

        return ImmutableClassDef(
            cls.type, cls.accessFlags, cls.superclass,
            cls.interfaces?.toList(),
            cls.sourceFile,
            cls.annotations?.map { ImmutableAnnotation(it.visibility, it.type, null) }?.toSet(),
            allFields,
            allMethods
        )
    }

    private fun toImmutableMethod(m: com.android.tools.smali.dexlib2.iface.Method): ImmutableMethod {
        return ImmutableMethod(
            m.definingClass, m.name,
            m.parameters?.map { ImmutableMethodParameter(it.type, null, it.name) },
            m.returnType, m.accessFlags,
            m.annotations?.map { ImmutableAnnotation(it.visibility, it.type, null) }?.toSet(),
            null,
            m.implementation?.let { impl ->
                ImmutableMethodImplementation(
                    impl.registerCount,
                    impl.instructions.toList(),
                    impl.tryBlocks.toList(),
                    impl.debugItems.toList()
                )
            }
        )
    }

    // ── Patch class ────────────────────────────────────────────

    private fun patchClass(cls: ClassDef, cfg: Config): ImmutableClassDef {
        val newMethods = cls.methods.map { method ->
            if (method.name == "onCreate" &&
                method.parameterTypes.firstOrNull() == "Landroid/os/Bundle;") {
                patchOnCreate(method, cls.type, cfg)
            } else {
                toImmutableMethod(method)
            }
        }

        val allFields = ((cls.staticFields ?: emptyList()) +
                        (cls.instanceFields ?: emptyList())).map {
            ImmutableField(it.definingClass, it.name, it.type,
                it.accessFlags, null, null, null)
        }

        return ImmutableClassDef(
            cls.type, cls.accessFlags, cls.superclass,
            cls.interfaces?.toList(), cls.sourceFile,
            cls.annotations?.map { ImmutableAnnotation(it.visibility, it.type, null) }?.toSet(),
            allFields,
            newMethods
        )
    }

    private fun patchOnCreate(
        method: com.android.tools.smali.dexlib2.iface.Method,
        classType: String,
        cfg: Config
    ): ImmutableMethod {
        val impl = method.implementation ?: return toImmutableMethod(method)

        val id = cfg.prefKey.replace(Regex("[^A-Za-z0-9]"), "_")
        val existingInstrs = impl.instructions.toList()

        var insertIdx = 0
        for ((i, instr) in existingInstrs.withIndex()) {
            if (instr.opcode == Opcode.INVOKE_VIRTUAL || instr.opcode == Opcode.INVOKE_SUPER) {
                val ref = (instr as? ReferenceInstruction)?.reference?.toString() ?: continue
                if ("onCreate(Landroid/os/Bundle;)V" in ref || "setContentView" in ref) {
                    insertIdx = i + 1
                    break
                }
            }
        }

        val origRegs  = impl.registerCount
        val newRegCount = origRegs + 3
        val v0 = origRegs
        val v1 = origRegs + 1
        val v2 = origRegs + 2
        val paramCount = (method.parameters?.size ?: 0) + 1 // +1 for this
        val p0 = newRegCount - paramCount

        val dialogInstrs = buildDialogCode(cfg, id, p0, v0, v1, v2)

        val allInstrs = existingInstrs.toMutableList()
        allInstrs.addAll(insertIdx, dialogInstrs)

        Log.d(tag, "הוזרק ב-$classType idx=$insertIdx regs:$origRegs→$newRegCount")

        return ImmutableMethod(
            method.definingClass, method.name,
            method.parameters?.map { ImmutableMethodParameter(it.type, null, it.name) },
            method.returnType, method.accessFlags,
            method.annotations?.map { ImmutableAnnotation(it.visibility, it.type, null) }?.toSet(),
            null,
            ImmutableMethodImplementation(
                newRegCount, allInstrs,
                impl.tryBlocks.toList(), impl.debugItems.toList()
            )
        )
    }

    // ── Build dialog instructions ──────────────────────────────

    private fun buildDialogCode(
        cfg: Config, id: String, p0: Int, v0: Int, v1: Int, v2: Int
    ): List<com.android.tools.smali.dexlib2.iface.instruction.Instruction> {

        fun str(s: String) = ImmutableStringReference(s)
        fun type(s: String) = ImmutableTypeReference(s)
        fun mref(cls: String, name: String, params: List<String>, ret: String) =
            ImmutableMethodReference(cls, name, params, ret)

        val list = mutableListOf<com.android.tools.smali.dexlib2.iface.instruction.Instruction>()

        // SharedPreferences check
        list += BuilderInstruction21c(Opcode.CONST_STRING, v1, str("zovex_pref_$id"))
        list += BuilderInstruction11n(Opcode.CONST_4, v2, 0)
        list += BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 3, p0, v1, v2, 0, 0,
            mref("Landroid/app/Activity;", "getSharedPreferences",
                listOf("Ljava/lang/String;", "I"), "Landroid/content/SharedPreferences;"))
        list += BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v0)
        list += BuilderInstruction21c(Opcode.CONST_STRING, v1, str("dismissed_$id"))
        list += BuilderInstruction35c(Opcode.INVOKE_INTERFACE, 3, v0, v1, v2, 0, 0,
            mref("Landroid/content/SharedPreferences;", "getBoolean",
                listOf("Ljava/lang/String;", "Z"), "Z"))
        list += BuilderInstruction11x(Opcode.MOVE_RESULT, v1)

        // כמה instructions יש בדיאלוג (אחרי ה-if-nez)
        val dialogBodySize = if (cfg.telegramUrl.isNotBlank()) 28 else 24
        // if-nez: קפוץ קדימה dialogBodySize+1 instructions
        list += BuilderInstruction21t(Opcode.IF_NEZ, v1, dialogBodySize + 1)

        // new AlertDialog.Builder(this)
        list += BuilderInstruction21c(Opcode.NEW_INSTANCE, v0,
            type("Landroidx/appcompat/app/AlertDialog\$Builder;"))
        list += BuilderInstruction35c(Opcode.INVOKE_DIRECT, 2, v0, p0, 0, 0, 0,
            mref("Landroidx/appcompat/app/AlertDialog\$Builder;", "<init>",
                listOf("Landroid/content/Context;"), "V"))

        // setTitle
        list += BuilderInstruction21c(Opcode.CONST_STRING, v1, str(cfg.title))
        list += BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 2, v0, v1, 0, 0, 0,
            mref("Landroidx/appcompat/app/AlertDialog\$Builder;", "setTitle",
                listOf("Ljava/lang/CharSequence;"),
                "Landroidx/appcompat/app/AlertDialog\$Builder;"))
        list += BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v0)

        // setMessage
        list += BuilderInstruction21c(Opcode.CONST_STRING, v1, str(cfg.description))
        list += BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 2, v0, v1, 0, 0, 0,
            mref("Landroidx/appcompat/app/AlertDialog\$Builder;", "setMessage",
                listOf("Ljava/lang/CharSequence;"),
                "Landroidx/appcompat/app/AlertDialog\$Builder;"))
        list += BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v0)

        // OK button
        list += BuilderInstruction21c(Opcode.CONST_STRING, v1, str(cfg.okText))
        list += BuilderInstruction21c(Opcode.NEW_INSTANCE, v2,
            type("Lcom/zovex/injected/Ok_$id;"))
        list += BuilderInstruction35c(Opcode.INVOKE_DIRECT, 1, v2, 0, 0, 0, 0,
            mref("Lcom/zovex/injected/Ok_$id;", "<init>", emptyList(), "V"))
        list += BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 3, v0, v1, v2, 0, 0,
            mref("Landroidx/appcompat/app/AlertDialog\$Builder;", "setPositiveButton",
                listOf("Ljava/lang/CharSequence;",
                    "Landroid/content/DialogInterface\$OnClickListener;"),
                "Landroidx/appcompat/app/AlertDialog\$Builder;"))
        list += BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v0)

        // Telegram (optional)
        if (cfg.telegramUrl.isNotBlank()) {
            list += BuilderInstruction21c(Opcode.CONST_STRING, v1,
                str("\u05d4\u05e6\u05d8\u05e8\u05e4\u05d5 \u05dc\u05d8\u05dc\u05d2\u05e8\u05dd"))
            list += BuilderInstruction21c(Opcode.NEW_INSTANCE, v2,
                type("Lcom/zovex/injected/Tg_$id;"))
            list += BuilderInstruction35c(Opcode.INVOKE_DIRECT, 2, v2, p0, 0, 0, 0,
                mref("Lcom/zovex/injected/Tg_$id;", "<init>",
                    listOf("Landroid/content/Context;"), "V"))
            list += BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 3, v0, v1, v2, 0, 0,
                mref("Landroidx/appcompat/app/AlertDialog\$Builder;", "setNeutralButton",
                    listOf("Ljava/lang/CharSequence;",
                        "Landroid/content/DialogInterface\$OnClickListener;"),
                    "Landroidx/appcompat/app/AlertDialog\$Builder;"))
            list += BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v0)
        }

        // Dismiss button
        list += BuilderInstruction21c(Opcode.CONST_STRING, v1,
            str("\u05d0\u05dc \u05ea\u05e6\u05d9\u05d2 \u05e9\u05d5\u05d1"))
        list += BuilderInstruction21c(Opcode.NEW_INSTANCE, v2,
            type("Lcom/zovex/injected/Dismiss_$id;"))
        list += BuilderInstruction35c(Opcode.INVOKE_DIRECT, 2, v2, p0, 0, 0, 0,
            mref("Lcom/zovex/injected/Dismiss_$id;", "<init>",
                listOf("Landroid/content/Context;"), "V"))
        list += BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 3, v0, v1, v2, 0, 0,
            mref("Landroidx/appcompat/app/AlertDialog\$Builder;", "setNegativeButton",
                listOf("Ljava/lang/CharSequence;",
                    "Landroid/content/DialogInterface\$OnClickListener;"),
                "Landroidx/appcompat/app/AlertDialog\$Builder;"))
        list += BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v0)

        // setCancelable(false)
        list += BuilderInstruction11n(Opcode.CONST_4, v1, 0)
        list += BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 2, v0, v1, 0, 0, 0,
            mref("Landroidx/appcompat/app/AlertDialog\$Builder;", "setCancelable",
                listOf("Z"), "Landroidx/appcompat/app/AlertDialog\$Builder;"))
        list += BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v0)

        // show()
        list += BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, v0, 0, 0, 0, 0,
            mref("Landroidx/appcompat/app/AlertDialog\$Builder;", "show",
                emptyList(), "Landroidx/appcompat/app/AlertDialog;"))

        // NOP — end label
        list += BuilderInstruction10x(Opcode.NOP)

        return list
    }

    // ── Build helper classes ───────────────────────────────────

    private fun buildDialogClasses(cfg: Config): List<ImmutableClassDef> {
        val id = cfg.prefKey.replace(Regex("[^A-Za-z0-9]"), "_")
        val list = mutableListOf<ImmutableClassDef>()
        list += buildOkClass(id)
        list += buildDismissClass(id)
        if (cfg.telegramUrl.isNotBlank()) list += buildTgClass(id, cfg.telegramUrl)
        return list
    }

    private fun buildOkClass(id: String): ImmutableClassDef {
        val type = "Lcom/zovex/injected/Ok_$id;"
        fun mref(cls: String, name: String, params: List<String>, ret: String) =
            ImmutableMethodReference(cls, name, params, ret)

        val init = ImmutableMethod(type, "<init>", null, "V",
            AccessFlags.PUBLIC.value or AccessFlags.CONSTRUCTOR.value,
            null, null,
            ImmutableMethodImplementation(1, listOf(
                BuilderInstruction35c(Opcode.INVOKE_DIRECT, 1, 0, 0, 0, 0, 0,
                    mref("Ljava/lang/Object;", "<init>", emptyList(), "V")),
                BuilderInstruction10x(Opcode.RETURN_VOID)
            ), null, null))

        val onClick = ImmutableMethod(type, "onClick",
            listOf(ImmutableMethodParameter("Landroid/content/DialogInterface;", null, null),
                ImmutableMethodParameter("I", null, null)),
            "V", AccessFlags.PUBLIC.value, null, null,
            ImmutableMethodImplementation(3, listOf(
                BuilderInstruction35c(Opcode.INVOKE_INTERFACE, 1, 1, 0, 0, 0, 0,
                    mref("Landroid/content/DialogInterface;", "dismiss", emptyList(), "V")),
                BuilderInstruction10x(Opcode.RETURN_VOID)
            ), null, null))

        return ImmutableClassDef(type, AccessFlags.PUBLIC.value,
            "Ljava/lang/Object;",
            listOf("Landroid/content/DialogInterface\$OnClickListener;"),
            null, null,
            emptyList<ImmutableField>(),
            listOf(init, onClick))
    }

    private fun buildDismissClass(id: String): ImmutableClassDef {
        val type = "Lcom/zovex/injected/Dismiss_$id;"
        fun mref(cls: String, name: String, params: List<String>, ret: String) =
            ImmutableMethodReference(cls, name, params, ret)
        val fref = ImmutableFieldReference(type, "ctx", "Landroid/content/Context;")
        val ctxField = ImmutableField(type, "ctx", "Landroid/content/Context;",
            AccessFlags.PRIVATE.value, null, null, null)

        val init = ImmutableMethod(type, "<init>",
            listOf(ImmutableMethodParameter("Landroid/content/Context;", null, null)),
            "V", AccessFlags.PUBLIC.value or AccessFlags.CONSTRUCTOR.value,
            null, null,
            ImmutableMethodImplementation(2, listOf(
                BuilderInstruction35c(Opcode.INVOKE_DIRECT, 1, 0, 0, 0, 0, 0,
                    mref("Ljava/lang/Object;", "<init>", emptyList(), "V")),
                BuilderInstruction22c(Opcode.IPUT_OBJECT, 1, 0, fref),
                BuilderInstruction10x(Opcode.RETURN_VOID)
            ), null, null))

        val onClick = ImmutableMethod(type, "onClick",
            listOf(ImmutableMethodParameter("Landroid/content/DialogInterface;", null, null),
                ImmutableMethodParameter("I", null, null)),
            "V", AccessFlags.PUBLIC.value, null, null,
            ImmutableMethodImplementation(4, listOf(
                BuilderInstruction22c(Opcode.IGET_OBJECT, 0, 2, fref),
                BuilderInstruction21c(Opcode.CONST_STRING, 1,
                    ImmutableStringReference("zovex_pref_$id")),
                BuilderInstruction11n(Opcode.CONST_4, 2, 0),
                BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 3, 0, 1, 2, 0, 0,
                    mref("Landroid/content/Context;", "getSharedPreferences",
                        listOf("Ljava/lang/String;", "I"),
                        "Landroid/content/SharedPreferences;")),
                BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0),
                BuilderInstruction35c(Opcode.INVOKE_INTERFACE, 1, 0, 0, 0, 0, 0,
                    mref("Landroid/content/SharedPreferences;", "edit",
                        emptyList(), "Landroid/content/SharedPreferences\$Editor;")),
                BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0),
                BuilderInstruction21c(Opcode.CONST_STRING, 1,
                    ImmutableStringReference("dismissed_$id")),
                BuilderInstruction11n(Opcode.CONST_4, 2, 1),
                BuilderInstruction35c(Opcode.INVOKE_INTERFACE, 3, 0, 1, 2, 0, 0,
                    mref("Landroid/content/SharedPreferences\$Editor;", "putBoolean",
                        listOf("Ljava/lang/String;", "Z"),
                        "Landroid/content/SharedPreferences\$Editor;")),
                BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0),
                BuilderInstruction35c(Opcode.INVOKE_INTERFACE, 1, 0, 0, 0, 0, 0,
                    mref("Landroid/content/SharedPreferences\$Editor;",
                        "apply", emptyList(), "V")),
                BuilderInstruction35c(Opcode.INVOKE_INTERFACE, 1, 3, 0, 0, 0, 0,
                    mref("Landroid/content/DialogInterface;", "dismiss", emptyList(), "V")),
                BuilderInstruction10x(Opcode.RETURN_VOID)
            ), null, null))

        return ImmutableClassDef(type, AccessFlags.PUBLIC.value,
            "Ljava/lang/Object;",
            listOf("Landroid/content/DialogInterface\$OnClickListener;"),
            null, null,
            listOf(ctxField),
            listOf(init, onClick))
    }

    private fun buildTgClass(id: String, url: String): ImmutableClassDef {
        val type = "Lcom/zovex/injected/Tg_$id;"
        fun mref(cls: String, name: String, params: List<String>, ret: String) =
            ImmutableMethodReference(cls, name, params, ret)
        val fref = ImmutableFieldReference(type, "ctx", "Landroid/content/Context;")
        val ctxField = ImmutableField(type, "ctx", "Landroid/content/Context;",
            AccessFlags.PRIVATE.value, null, null, null)

        val init = ImmutableMethod(type, "<init>",
            listOf(ImmutableMethodParameter("Landroid/content/Context;", null, null)),
            "V", AccessFlags.PUBLIC.value or AccessFlags.CONSTRUCTOR.value,
            null, null,
            ImmutableMethodImplementation(2, listOf(
                BuilderInstruction35c(Opcode.INVOKE_DIRECT, 1, 0, 0, 0, 0, 0,
                    mref("Ljava/lang/Object;", "<init>", emptyList(), "V")),
                BuilderInstruction22c(Opcode.IPUT_OBJECT, 1, 0, fref),
                BuilderInstruction10x(Opcode.RETURN_VOID)
            ), null, null))

        val onClick = ImmutableMethod(type, "onClick",
            listOf(ImmutableMethodParameter("Landroid/content/DialogInterface;", null, null),
                ImmutableMethodParameter("I", null, null)),
            "V", AccessFlags.PUBLIC.value, null, null,
            ImmutableMethodImplementation(4, listOf(
                BuilderInstruction22c(Opcode.IGET_OBJECT, 0, 2, fref),
                BuilderInstruction21c(Opcode.CONST_STRING, 1, ImmutableStringReference(url)),
                BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 1, 0, 0, 0, 0,
                    mref("Landroid/net/Uri;", "parse",
                        listOf("Ljava/lang/String;"), "Landroid/net/Uri;")),
                BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1),
                BuilderInstruction21c(Opcode.NEW_INSTANCE, 2,
                    ImmutableTypeReference("Landroid/content/Intent;")),
                BuilderInstruction21c(Opcode.CONST_STRING, 3,
                    ImmutableStringReference("android.intent.action.VIEW")),
                BuilderInstruction35c(Opcode.INVOKE_DIRECT, 3, 2, 3, 1, 0, 0,
                    mref("Landroid/content/Intent;", "<init>",
                        listOf("Ljava/lang/String;", "Landroid/net/Uri;"), "V")),
                BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 2, 0, 2, 0, 0, 0,
                    mref("Landroid/content/Context;", "startActivity",
                        listOf("Landroid/content/Intent;"), "V")),
                BuilderInstruction35c(Opcode.INVOKE_INTERFACE, 1, 3, 0, 0, 0, 0,
                    mref("Landroid/content/DialogInterface;", "dismiss", emptyList(), "V")),
                BuilderInstruction10x(Opcode.RETURN_VOID)
            ), null, null))

        return ImmutableClassDef(type, AccessFlags.PUBLIC.value,
            "Ljava/lang/Object;",
            listOf("Landroid/content/DialogInterface\$OnClickListener;"),
            null, null,
            listOf(ctxField),
            listOf(init, onClick))
    }

    // ── Remove dialogs ─────────────────────────────────────────

    private fun removeDialogFromClass(cls: ClassDef): ImmutableClassDef {
        val newMethods = cls.methods.map { method ->
            val impl = method.implementation ?: return@map toImmutableMethod(method)
            val instrs = impl.instructions.toList()
            val showIdx = instrs.indexOfFirst { instr ->
                instr.opcode == Opcode.INVOKE_VIRTUAL &&
                (instr as? ReferenceInstruction)?.reference?.toString()
                    ?.contains("->show()") == true
            }
            if (showIdx <= 0) return@map toImmutableMethod(method)

            val newInstrs = listOf(BuilderInstruction10x(Opcode.RETURN_VOID)) +
                instrs.drop(showIdx + 1)

            ImmutableMethod(
                method.definingClass, method.name,
                method.parameters?.map { ImmutableMethodParameter(it.type, null, it.name) },
                method.returnType, method.accessFlags,
                method.annotations?.map { ImmutableAnnotation(it.visibility, it.type, null) }?.toSet(),
                null,
                ImmutableMethodImplementation(impl.registerCount, newInstrs,
                    impl.tryBlocks.toList(), impl.debugItems.toList())
            )
        }

        val allFields = ((cls.staticFields ?: emptyList()) +
                        (cls.instanceFields ?: emptyList())).map {
            ImmutableField(it.definingClass, it.name, it.type,
                it.accessFlags, null, null, null)
        }

        return ImmutableClassDef(
            cls.type, cls.accessFlags, cls.superclass,
            cls.interfaces?.toList(), cls.sourceFile,
            cls.annotations?.map { ImmutableAnnotation(it.visibility, it.type, null) }?.toSet(),
            allFields,
            newMethods
        )
    }

    // ── Write DEX ──────────────────────────────────────────────

    private fun writeDex(classes: List<ClassDef>, outFile: File, opcodes: Opcodes) {
        val pool = DexPool(opcodes)
        for (cls in classes) pool.internClass(cls)
        pool.writeTo(FileDataStore(outFile))
    }
}

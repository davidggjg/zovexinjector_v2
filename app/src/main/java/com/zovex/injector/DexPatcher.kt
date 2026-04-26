package com.zovex.injector

import android.util.Log
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.DexFileFactory
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation
import com.android.tools.smali.dexlib2.builder.instruction.*
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.immutable.*
import com.android.tools.smali.dexlib2.immutable.reference.*
import com.android.tools.smali.dexlib2.writer.io.FileDataStore
import com.android.tools.smali.dexlib2.writer.pool.DexPool
import java.io.File
import java.io.IOException

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
            val hasDialog = cls.methods.any { method ->
                method.implementation?.instructions?.any { instr ->
                    instr.opcode == Opcode.INVOKE_VIRTUAL &&
                    (instr as? ReferenceInstruction)?.reference?.toString()
                        ?.contains("AlertDialog") == true
                } == true
            }
            if (hasDialog) removeDialogFromClass(cls) else cls
        }

        val outDex = File(dexFile.parent, "patched_${dexFile.name}")
        writeDex(newClasses, outDex, dex.opcodes)
        return outDex
    }

    // ── Patch class ────────────────────────────────────────────

    private fun patchClass(cls: ClassDef, cfg: Config): ClassDef {
        val newMethods = cls.methods.map { method ->
            if (method.name == "onCreate" &&
                method.parameterTypes.firstOrNull() == "Landroid/os/Bundle;") {
                patchOnCreate(method, cls.type, cfg)
            } else {
                ImmutableMethod(
                    method.definingClass, method.name,
                    method.parameters?.map { ImmutableMethodParameter(it.type, null, it.name) },
                    method.returnType, method.accessFlags,
                    method.annotations?.map { ImmutableAnnotation(it.visibility, it.type, null) }?.toSet(),
                    null,
                    method.implementation?.let { ImmutableMethodImplementation(
                        it.registerCount,
                        it.instructions.toList(),
                        it.tryBlocks.toList(),
                        it.debugItems.toList()
                    )}
                )
            }
        }

        return ImmutableClassDef(
            cls.type, cls.accessFlags, cls.superclass,
            cls.interfaces?.toList(),
            cls.sourceFile,
            cls.annotations?.map { ImmutableAnnotation(it.visibility, it.type, null) }?.toSet(),
            null, null,
            newMethods.toList()
        )
    }

    private fun patchOnCreate(
        method: com.android.tools.smali.dexlib2.iface.Method,
        classType: String,
        cfg: Config
    ): ImmutableMethod {
        val impl = method.implementation
            ?: return ImmutableMethod(
                method.definingClass, method.name,
                method.parameters?.map { ImmutableMethodParameter(it.type, null, it.name) },
                method.returnType, method.accessFlags,
                method.annotations?.map { ImmutableAnnotation(it.visibility, it.type, null) }?.toSet(),
                null, null
            )

        val id = cfg.prefKey.replace(Regex("[^A-Za-z0-9]"), "_")
        val instructions = impl.instructions.toList()

        // מצא נקודת הזרקה
        var insertIdx = 0
        for ((i, instr) in instructions.withIndex()) {
            if (instr.opcode == Opcode.INVOKE_VIRTUAL || instr.opcode == Opcode.INVOKE_SUPER) {
                val ref = (instr as? ReferenceInstruction)?.reference?.toString() ?: continue
                if ("onCreate(Landroid/os/Bundle;)V" in ref || "setContentView" in ref) {
                    insertIdx = i + 1
                    break
                }
            }
        }

        // מספר registers קיים
        val existingRegs = impl.registerCount
        // registers נוספים שנצטרך: v0, v1, v2 (3 registers)
        val newRegCount = existingRegs + 3
        // ה-registers החדשים (אחרי הקיימים)
        val v0 = existingRegs
        val v1 = existingRegs + 1
        val v2 = existingRegs + 2
        // p0 = this = register ראשון מהפרמטרים
        val p0 = newRegCount - method.parameters.size - 1

        val dialogInstrs = buildDialogInstructions(cfg, id, p0, v0, v1, v2)

        val allInstrs = instructions.toMutableList()
        allInstrs.addAll(insertIdx, dialogInstrs)

        Log.d(tag, "הוזרק ב-$classType, insertIdx=$insertIdx, registers: $existingRegs→$newRegCount")

        return ImmutableMethod(
            method.definingClass, method.name,
            method.parameters?.map { ImmutableMethodParameter(it.type, null, it.name) },
            method.returnType, method.accessFlags,
            method.annotations?.map { ImmutableAnnotation(it.visibility, it.type, null) }?.toSet(),
            null,
            ImmutableMethodImplementation(
                newRegCount,
                allInstrs,
                impl.tryBlocks.toList(),
                impl.debugItems.toList()
            )
        )
    }

    // ── Build dialog instructions ──────────────────────────────

    private fun buildDialogInstructions(
        cfg: Config, id: String, p0: Int, v0: Int, v1: Int, v2: Int
    ): List<com.android.tools.smali.dexlib2.iface.instruction.Instruction> {

        val instrs = mutableListOf<com.android.tools.smali.dexlib2.iface.instruction.Instruction>()

        fun str(s: String) = ImmutableStringReference(s)
        fun type(s: String) = ImmutableTypeReference(s)
        fun mref(cls: String, name: String, params: List<String>, ret: String) =
            ImmutableMethodReference(cls, name, params, ret)

        // SharedPreferences — בדוק אם הוצג
        instrs += ImmutableInstruction21c(Opcode.CONST_STRING, v1, str("zovex_pref_$id"))
        instrs += ImmutableInstruction11n(Opcode.CONST_4, v2, 0)
        instrs += ImmutableInstruction35c(Opcode.INVOKE_VIRTUAL, 3, p0, v1, v2, 0, 0,
            mref("Landroid/app/Activity;", "getSharedPreferences",
                listOf("Ljava/lang/String;", "I"), "Landroid/content/SharedPreferences;"))
        instrs += ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, v0)
        instrs += ImmutableInstruction21c(Opcode.CONST_STRING, v1, str("dismissed_$id"))
        instrs += ImmutableInstruction35c(Opcode.INVOKE_INTERFACE, 3, v0, v1, v2, 0, 0,
            mref("Landroid/content/SharedPreferences;", "getBoolean",
                listOf("Ljava/lang/String;", "Z"), "Z"))
        instrs += ImmutableInstruction11x(Opcode.MOVE_RESULT, v1)

        // אם הוצג כבר — דלג (if-nez → skip N instructions)
        // נחשב: כמה instructions יש בדיאלוג (אחרי ה-if-nez)
        // נשים NOP בסוף ונחזור להוסיף offset אחרי הבנייה
        val skipTarget = 100 // placeholder — יוחלף
        instrs += ImmutableInstruction21t(Opcode.IF_NEZ, v1, skipTarget)

        val dialogStart = instrs.size

        // new AlertDialog.Builder(this)
        instrs += ImmutableInstruction21c(Opcode.NEW_INSTANCE, v0,
            type("Landroidx/appcompat/app/AlertDialog\$Builder;"))
        instrs += ImmutableInstruction35c(Opcode.INVOKE_DIRECT, 2, v0, p0, 0, 0, 0,
            mref("Landroidx/appcompat/app/AlertDialog\$Builder;", "<init>",
                listOf("Landroid/content/Context;"), "V"))

        // setTitle
        instrs += ImmutableInstruction21c(Opcode.CONST_STRING, v1, str(cfg.title))
        instrs += ImmutableInstruction35c(Opcode.INVOKE_VIRTUAL, 2, v0, v1, 0, 0, 0,
            mref("Landroidx/appcompat/app/AlertDialog\$Builder;", "setTitle",
                listOf("Ljava/lang/CharSequence;"),
                "Landroidx/appcompat/app/AlertDialog\$Builder;"))
        instrs += ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, v0)

        // setMessage
        instrs += ImmutableInstruction21c(Opcode.CONST_STRING, v1, str(cfg.description))
        instrs += ImmutableInstruction35c(Opcode.INVOKE_VIRTUAL, 2, v0, v1, 0, 0, 0,
            mref("Landroidx/appcompat/app/AlertDialog\$Builder;", "setMessage",
                listOf("Ljava/lang/CharSequence;"),
                "Landroidx/appcompat/app/AlertDialog\$Builder;"))
        instrs += ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, v0)

        // OK button
        instrs += ImmutableInstruction21c(Opcode.CONST_STRING, v1, str(cfg.okText))
        instrs += ImmutableInstruction21c(Opcode.NEW_INSTANCE, v2,
            type("Lcom/zovex/injected/Ok_$id;"))
        instrs += ImmutableInstruction35c(Opcode.INVOKE_DIRECT, 1, v2, 0, 0, 0, 0,
            mref("Lcom/zovex/injected/Ok_$id;", "<init>", emptyList(), "V"))
        instrs += ImmutableInstruction35c(Opcode.INVOKE_VIRTUAL, 3, v0, v1, v2, 0, 0,
            mref("Landroidx/appcompat/app/AlertDialog\$Builder;", "setPositiveButton",
                listOf("Ljava/lang/CharSequence;",
                    "Landroid/content/DialogInterface\$OnClickListener;"),
                "Landroidx/appcompat/app/AlertDialog\$Builder;"))
        instrs += ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, v0)

        // Telegram (optional)
        if (cfg.telegramUrl.isNotBlank()) {
            instrs += ImmutableInstruction21c(Opcode.CONST_STRING, v1,
                str("\u05d4\u05e6\u05d8\u05e8\u05e4\u05d5 \u05dc\u05d8\u05dc\u05d2\u05e8\u05dd"))
            instrs += ImmutableInstruction21c(Opcode.NEW_INSTANCE, v2,
                type("Lcom/zovex/injected/Tg_$id;"))
            instrs += ImmutableInstruction35c(Opcode.INVOKE_DIRECT, 2, v2, p0, 0, 0, 0,
                mref("Lcom/zovex/injected/Tg_$id;", "<init>",
                    listOf("Landroid/content/Context;"), "V"))
            instrs += ImmutableInstruction35c(Opcode.INVOKE_VIRTUAL, 3, v0, v1, v2, 0, 0,
                mref("Landroidx/appcompat/app/AlertDialog\$Builder;", "setNeutralButton",
                    listOf("Ljava/lang/CharSequence;",
                        "Landroid/content/DialogInterface\$OnClickListener;"),
                    "Landroidx/appcompat/app/AlertDialog\$Builder;"))
            instrs += ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, v0)
        }

        // Dismiss button
        instrs += ImmutableInstruction21c(Opcode.CONST_STRING, v1,
            str("\u05d0\u05dc \u05ea\u05e6\u05d9\u05d2 \u05e9\u05d5\u05d1"))
        instrs += ImmutableInstruction21c(Opcode.NEW_INSTANCE, v2,
            type("Lcom/zovex/injected/Dismiss_$id;"))
        instrs += ImmutableInstruction35c(Opcode.INVOKE_DIRECT, 2, v2, p0, 0, 0, 0,
            mref("Lcom/zovex/injected/Dismiss_$id;", "<init>",
                listOf("Landroid/content/Context;"), "V"))
        instrs += ImmutableInstruction35c(Opcode.INVOKE_VIRTUAL, 3, v0, v1, v2, 0, 0,
            mref("Landroidx/appcompat/app/AlertDialog\$Builder;", "setNegativeButton",
                listOf("Ljava/lang/CharSequence;",
                    "Landroid/content/DialogInterface\$OnClickListener;"),
                "Landroidx/appcompat/app/AlertDialog\$Builder;"))
        instrs += ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, v0)

        // setCancelable(false)
        instrs += ImmutableInstruction11n(Opcode.CONST_4, v1, 0)
        instrs += ImmutableInstruction35c(Opcode.INVOKE_VIRTUAL, 2, v0, v1, 0, 0, 0,
            mref("Landroidx/appcompat/app/AlertDialog\$Builder;", "setCancelable",
                listOf("Z"), "Landroidx/appcompat/app/AlertDialog\$Builder;"))
        instrs += ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, v0)

        // show()
        instrs += ImmutableInstruction35c(Opcode.INVOKE_VIRTUAL, 1, v0, 0, 0, 0, 0,
            mref("Landroidx/appcompat/app/AlertDialog\$Builder;", "show",
                emptyList(), "Landroidx/appcompat/app/AlertDialog;"))

        // NOP — end label
        instrs += ImmutableInstruction10x(Opcode.NOP)

        // תקן את ה-if-nez offset
        val skipCount = instrs.size - dialogStart
        instrs[dialogStart - 1] = ImmutableInstruction21t(Opcode.IF_NEZ, v1, skipCount)

        return instrs
    }

    // ── Build dialog helper classes ────────────────────────────

    private fun buildDialogClasses(cfg: Config): List<ClassDef> {
        val id = cfg.prefKey.replace(Regex("[^A-Za-z0-9]"), "_")
        val classes = mutableListOf<ClassDef>()
        classes += buildOkClass(id)
        classes += buildDismissClass(id)
        if (cfg.telegramUrl.isNotBlank()) classes += buildTgClass(id, cfg.telegramUrl)
        return classes
    }

    private fun buildOkClass(id: String): ImmutableClassDef {
        fun mref(cls: String, name: String, params: List<String>, ret: String) =
            ImmutableMethodReference(cls, name, params, ret)

        val init = ImmutableMethod(
            "Lcom/zovex/injected/Ok_$id;", "<init>",
            null, "V",
            AccessFlags.PUBLIC.value or AccessFlags.CONSTRUCTOR.value,
            null, null,
            ImmutableMethodImplementation(1, listOf(
                ImmutableInstruction35c(Opcode.INVOKE_DIRECT, 1, 0, 0, 0, 0, 0,
                    mref("Ljava/lang/Object;", "<init>", emptyList(), "V")),
                ImmutableInstruction10x(Opcode.RETURN_VOID)
            ), null, null)
        )

        val onClick = ImmutableMethod(
            "Lcom/zovex/injected/Ok_$id;", "onClick",
            listOf(
                ImmutableMethodParameter("Landroid/content/DialogInterface;", null, null),
                ImmutableMethodParameter("I", null, null)
            ), "V", AccessFlags.PUBLIC.value, null, null,
            ImmutableMethodImplementation(3, listOf(
                ImmutableInstruction35c(Opcode.INVOKE_INTERFACE, 1, 1, 0, 0, 0, 0,
                    mref("Landroid/content/DialogInterface;", "dismiss", emptyList(), "V")),
                ImmutableInstruction10x(Opcode.RETURN_VOID)
            ), null, null)
        )

        return ImmutableClassDef(
            "Lcom/zovex/injected/Ok_$id;",
            AccessFlags.PUBLIC.value,
            "Ljava/lang/Object;",
            listOf("Landroid/content/DialogInterface\$OnClickListener;"),
            null, null, null, null,
            listOf(init, onClick)
        )
    }

    private fun buildDismissClass(id: String): ImmutableClassDef {
        fun mref(cls: String, name: String, params: List<String>, ret: String) =
            ImmutableMethodReference(cls, name, params, ret)
        fun fref(cls: String, name: String, type: String) =
            ImmutableFieldReference(cls, name, type)

        val ctxField = ImmutableField(
            "Lcom/zovex/injected/Dismiss_$id;", "ctx",
            "Landroid/content/Context;", AccessFlags.PRIVATE.value,
            null, null, null)

        val init = ImmutableMethod(
            "Lcom/zovex/injected/Dismiss_$id;", "<init>",
            listOf(ImmutableMethodParameter("Landroid/content/Context;", null, null)),
            "V", AccessFlags.PUBLIC.value or AccessFlags.CONSTRUCTOR.value,
            null, null,
            ImmutableMethodImplementation(2, listOf(
                ImmutableInstruction35c(Opcode.INVOKE_DIRECT, 1, 0, 0, 0, 0, 0,
                    mref("Ljava/lang/Object;", "<init>", emptyList(), "V")),
                ImmutableInstruction22c(Opcode.IPUT_OBJECT, 1, 0,
                    fref("Lcom/zovex/injected/Dismiss_$id;", "ctx", "Landroid/content/Context;")),
                ImmutableInstruction10x(Opcode.RETURN_VOID)
            ), null, null)
        )

        val onClick = ImmutableMethod(
            "Lcom/zovex/injected/Dismiss_$id;", "onClick",
            listOf(
                ImmutableMethodParameter("Landroid/content/DialogInterface;", null, null),
                ImmutableMethodParameter("I", null, null)
            ), "V", AccessFlags.PUBLIC.value, null, null,
            ImmutableMethodImplementation(4, listOf(
                ImmutableInstruction22c(Opcode.IGET_OBJECT, 0, 2,
                    fref("Lcom/zovex/injected/Dismiss_$id;", "ctx", "Landroid/content/Context;")),
                ImmutableInstruction21c(Opcode.CONST_STRING, 1,
                    ImmutableStringReference("zovex_pref_$id")),
                ImmutableInstruction11n(Opcode.CONST_4, 2, 0),
                ImmutableInstruction35c(Opcode.INVOKE_VIRTUAL, 3, 0, 1, 2, 0, 0,
                    mref("Landroid/content/Context;", "getSharedPreferences",
                        listOf("Ljava/lang/String;", "I"),
                        "Landroid/content/SharedPreferences;")),
                ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0),
                ImmutableInstruction35c(Opcode.INVOKE_INTERFACE, 1, 0, 0, 0, 0, 0,
                    mref("Landroid/content/SharedPreferences;", "edit",
                        emptyList(), "Landroid/content/SharedPreferences\$Editor;")),
                ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0),
                ImmutableInstruction21c(Opcode.CONST_STRING, 1,
                    ImmutableStringReference("dismissed_$id")),
                ImmutableInstruction11n(Opcode.CONST_4, 2, 1),
                ImmutableInstruction35c(Opcode.INVOKE_INTERFACE, 3, 0, 1, 2, 0, 0,
                    mref("Landroid/content/SharedPreferences\$Editor;", "putBoolean",
                        listOf("Ljava/lang/String;", "Z"),
                        "Landroid/content/SharedPreferences\$Editor;")),
                ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0),
                ImmutableInstruction35c(Opcode.INVOKE_INTERFACE, 1, 0, 0, 0, 0, 0,
                    mref("Landroid/content/SharedPreferences\$Editor;", "apply",
                        emptyList(), "V")),
                ImmutableInstruction35c(Opcode.INVOKE_INTERFACE, 1, 3, 0, 0, 0, 0,
                    mref("Landroid/content/DialogInterface;", "dismiss", emptyList(), "V")),
                ImmutableInstruction10x(Opcode.RETURN_VOID)
            ), null, null)
        )

        return ImmutableClassDef(
            "Lcom/zovex/injected/Dismiss_$id;",
            AccessFlags.PUBLIC.value,
            "Ljava/lang/Object;",
            listOf("Landroid/content/DialogInterface\$OnClickListener;"),
            null, null, null,
            listOf(ctxField),
            listOf(init, onClick)
        )
    }

    private fun buildTgClass(id: String, url: String): ImmutableClassDef {
        fun mref(cls: String, name: String, params: List<String>, ret: String) =
            ImmutableMethodReference(cls, name, params, ret)
        fun fref(cls: String, name: String, type: String) =
            ImmutableFieldReference(cls, name, type)

        val ctxField = ImmutableField(
            "Lcom/zovex/injected/Tg_$id;", "ctx",
            "Landroid/content/Context;", AccessFlags.PRIVATE.value,
            null, null, null)

        val init = ImmutableMethod(
            "Lcom/zovex/injected/Tg_$id;", "<init>",
            listOf(ImmutableMethodParameter("Landroid/content/Context;", null, null)),
            "V", AccessFlags.PUBLIC.value or AccessFlags.CONSTRUCTOR.value,
            null, null,
            ImmutableMethodImplementation(2, listOf(
                ImmutableInstruction35c(Opcode.INVOKE_DIRECT, 1, 0, 0, 0, 0, 0,
                    mref("Ljava/lang/Object;", "<init>", emptyList(), "V")),
                ImmutableInstruction22c(Opcode.IPUT_OBJECT, 1, 0,
                    fref("Lcom/zovex/injected/Tg_$id;", "ctx", "Landroid/content/Context;")),
                ImmutableInstruction10x(Opcode.RETURN_VOID)
            ), null, null)
        )

        val onClick = ImmutableMethod(
            "Lcom/zovex/injected/Tg_$id;", "onClick",
            listOf(
                ImmutableMethodParameter("Landroid/content/DialogInterface;", null, null),
                ImmutableMethodParameter("I", null, null)
            ), "V", AccessFlags.PUBLIC.value, null, null,
            ImmutableMethodImplementation(4, listOf(
                ImmutableInstruction22c(Opcode.IGET_OBJECT, 0, 2,
                    fref("Lcom/zovex/injected/Tg_$id;", "ctx", "Landroid/content/Context;")),
                ImmutableInstruction21c(Opcode.CONST_STRING, 1, ImmutableStringReference(url)),
                ImmutableInstruction35c(Opcode.INVOKE_STATIC, 1, 1, 0, 0, 0, 0,
                    mref("Landroid/net/Uri;", "parse",
                        listOf("Ljava/lang/String;"), "Landroid/net/Uri;")),
                ImmutableInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1),
                ImmutableInstruction21c(Opcode.NEW_INSTANCE, 2,
                    ImmutableTypeReference("Landroid/content/Intent;")),
                ImmutableInstruction21c(Opcode.CONST_STRING, 3,
                    ImmutableStringReference("android.intent.action.VIEW")),
                ImmutableInstruction35c(Opcode.INVOKE_DIRECT, 3, 2, 3, 1, 0, 0,
                    mref("Landroid/content/Intent;", "<init>",
                        listOf("Ljava/lang/String;", "Landroid/net/Uri;"), "V")),
                ImmutableInstruction35c(Opcode.INVOKE_VIRTUAL, 2, 0, 2, 0, 0, 0,
                    mref("Landroid/content/Context;", "startActivity",
                        listOf("Landroid/content/Intent;"), "V")),
                ImmutableInstruction35c(Opcode.INVOKE_INTERFACE, 1, 3, 0, 0, 0, 0,
                    mref("Landroid/content/DialogInterface;", "dismiss", emptyList(), "V")),
                ImmutableInstruction10x(Opcode.RETURN_VOID)
            ), null, null)
        )

        return ImmutableClassDef(
            "Lcom/zovex/injected/Tg_$id;",
            AccessFlags.PUBLIC.value,
            "Ljava/lang/Object;",
            listOf("Landroid/content/DialogInterface\$OnClickListener;"),
            null, null, null,
            listOf(ctxField),
            listOf(init, onClick)
        )
    }

    // ── Remove dialogs ─────────────────────────────────────────

    private fun removeDialogFromClass(cls: ClassDef): ImmutableClassDef {
        val newMethods = cls.methods.map { method ->
            val impl = method.implementation ?: return@map ImmutableMethod(
                method.definingClass, method.name,
                method.parameters?.map { ImmutableMethodParameter(it.type, null, it.name) },
                method.returnType, method.accessFlags,
                method.annotations?.map { ImmutableAnnotation(it.visibility, it.type, null) }?.toSet(),
                null, null
            )

            val instrs = impl.instructions.toList()
            val showIdx = instrs.indexOfFirst { instr ->
                instr.opcode == Opcode.INVOKE_VIRTUAL &&
                (instr as? ReferenceInstruction)?.reference?.toString()?.contains("->show()") == true
            }

            if (showIdx <= 0) return@map ImmutableMethod(
                method.definingClass, method.name,
                method.parameters?.map { ImmutableMethodParameter(it.type, null, it.name) },
                method.returnType, method.accessFlags,
                method.annotations?.map { ImmutableAnnotation(it.visibility, it.type, null) }?.toSet(),
                null,
                ImmutableMethodImplementation(
                    impl.registerCount, instrs,
                    impl.tryBlocks.toList(), impl.debugItems.toList()
                )
            )

            // הוסף return-void בתחילת ה-method
            val newInstrs = listOf(ImmutableInstruction10x(Opcode.RETURN_VOID)) +
                instrs.drop(showIdx + 1)

            ImmutableMethod(
                method.definingClass, method.name,
                method.parameters?.map { ImmutableMethodParameter(it.type, null, it.name) },
                method.returnType, method.accessFlags,
                method.annotations?.map { ImmutableAnnotation(it.visibility, it.type, null) }?.toSet(),
                null,
                ImmutableMethodImplementation(
                    impl.registerCount, newInstrs,
                    impl.tryBlocks.toList(), impl.debugItems.toList()
                )
            )
        }

        return ImmutableClassDef(
            cls.type, cls.accessFlags, cls.superclass,
            cls.interfaces?.toList(), cls.sourceFile,
            cls.annotations?.map { ImmutableAnnotation(it.visibility, it.type, null) }?.toSet(),
            null, null,
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

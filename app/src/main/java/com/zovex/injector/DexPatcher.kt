package com.zovex.injector

import android.util.Log
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.DexFileFactory
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation
import com.android.tools.smali.dexlib2.builder.instruction.*
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.DexFile
import com.android.tools.smali.dexlib2.iface.Method
import com.android.tools.smali.dexlib2.iface.instruction.Instruction
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.android.tools.smali.dexlib2.iface.reference.StringReference
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.builder.MethodLocation
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.writer.io.FileDataStore
import com.android.tools.smali.dexlib2.writer.pool.DexPool
import java.io.File
import java.io.IOException

/**
 * מזריק דיאלוג ישירות לתוך DEX bytecode
 * ללא smali/baksmali — עובד על כל APK
 */
class DexPatcher {

    private val tag = "DexPatcher"

    data class Config(
        val title: String,
        val description: String,
        val okText: String = "אישור",
        val telegramUrl: String = "",
        val prefKey: String = "zovex_v1"
    )

    /**
     * מזריק דיאלוג ל-DEX
     * מחזיר DEX חדש עם ההזרקה
     */
    fun injectDialog(dexFile: File, cfg: Config, launcherClass: String): File {
        val dex = DexFileFactory.loadDexFile(dexFile, Opcodes.getDefault())
        val target = launcherClass.replace('.', '/')
        val targetType = "L$target;"

        val newClasses = dex.classes.map { cls ->
            if (cls.type == targetType) {
                patchClass(cls, cfg)
            } else cls
        }.toMutableList()

        // הוסף classes של הדיאלוג
        newClasses.addAll(buildDialogClasses(cfg))

        val outDex = File(dexFile.parent, "patched_${dexFile.name}")
        writeDex(newClasses, outDex, dex.opcodes)
        return outDex
    }

    /**
     * מחק דיאלוגים מ-DEX
     */
    fun deleteDialogs(dexFile: File): File {
        val dex = DexFileFactory.loadDexFile(dexFile, Opcodes.getDefault())

        val newClasses = dex.classes.map { cls ->
            val hasDialog = cls.methods.any { method ->
                method.implementation?.instructions?.any { instr ->
                    instr.opcode == Opcode.INVOKE_VIRTUAL &&
                    (instr as? ReferenceInstruction)?.reference?.toString()?.contains("AlertDialog") == true
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
            if (method.name == "onCreate" && method.parameterTypes.firstOrNull() == "Landroid/os/Bundle;") {
                patchOnCreate(method, cls.type, cfg)
            } else method
        }

        return ImmutableClassDef(
            cls.type, cls.accessFlags, cls.superclass,
            cls.interfaces, cls.sourceFile,
            cls.annotations, cls.staticFields,
            cls.instanceFields, newMethods
        )
    }

    private fun patchOnCreate(method: Method, classType: String, cfg: Config): Method {
        val impl = method.implementation
            ?: return method

        val id = cfg.prefKey.replace(Regex("[^A-Za-z0-9]"), "_")
        val mutableImpl = MutableMethodImplementation(impl)

        // מצא את הנקודה הנכונה להזרקה — אחרי super.onCreate או setContentView
        var insertIdx = 0
        val instructions = impl.instructions.toList()
        for ((i, instr) in instructions.withIndex()) {
            if (instr.opcode == Opcode.INVOKE_VIRTUAL || instr.opcode == Opcode.INVOKE_SUPER) {
                val ref = (instr as? ReferenceInstruction)?.reference?.toString() ?: continue
                if ("onCreate(Landroid/os/Bundle;)V" in ref || "setContentView" in ref) {
                    insertIdx = i + 1
                    break
                }
            }
        }

        // בנה instructions לדיאלוג
        val dialogInstrs = buildDialogInstructions(cfg, id, classType, mutableImpl.registerCount)

        // הוסף את ה-instructions
        val label = mutableImpl.newLabelForIndex(insertIdx)
        for ((i, instr) in dialogInstrs.withIndex()) {
            mutableImpl.addInstruction(insertIdx + i, instr)
        }

        Log.d(tag, "הוזרק onCreate ב-$classType")

        return ImmutableMethod(
            method.definingClass, method.name,
            method.parameters, method.returnType,
            method.accessFlags, method.annotations,
            ImmutableMethodImplementation(
                maxOf(mutableImpl.registerCount, impl.registerCount + 14),
                mutableImpl.instructions.map { it },
                impl.tryBlocks,
                impl.debugItems
            )
        )
    }

    // ── Build dialog instructions ──────────────────────────────

    private fun buildDialogInstructions(
        cfg: Config, id: String, classType: String, regCount: Int
    ): List<com.android.tools.smali.dexlib2.builder.BuilderInstruction> {

        val v0 = regCount      // register חופשי
        val v1 = regCount + 1
        val v2 = regCount + 2
        val p0 = 0             // this

        val instrs = mutableListOf<com.android.tools.smali.dexlib2.builder.BuilderInstruction>()

        // SharedPreferences — בדוק אם הוצג כבר
        instrs += BuilderInstruction21c(
            Opcode.CONST_STRING, v1,
            ImmutableStringReference("zovex_pref_$id"))
        instrs += BuilderInstruction11n(Opcode.CONST_4, v2, 0)
        instrs += BuilderInstruction35c(
            Opcode.INVOKE_VIRTUAL, 3, p0, v1, v2, 0, 0,
            ImmutableMethodReference(
                "Landroid/app/Activity;", "getSharedPreferences",
                listOf("Ljava/lang/String;", "I"), "Landroid/content/SharedPreferences;"))
        instrs += BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v0)
        instrs += BuilderInstruction21c(
            Opcode.CONST_STRING, v1,
            ImmutableStringReference("dismissed_$id"))
        instrs += BuilderInstruction35c(
            Opcode.INVOKE_INTERFACE, 3, v0, v1, v2, 0, 0,
            ImmutableMethodReference(
                "Landroid/content/SharedPreferences;", "getBoolean",
                listOf("Ljava/lang/String;", "Z"), "Z"))
        instrs += BuilderInstruction11x(Opcode.MOVE_RESULT, v1)

        // if already dismissed — skip
        val endLabel = com.android.tools.smali.dexlib2.builder.Label()
        instrs += BuilderInstruction21t(Opcode.IF_NEZ, v1, endLabel)

        // new AlertDialog.Builder(this)
        instrs += BuilderInstruction21c(
            Opcode.NEW_INSTANCE, v0,
            ImmutableTypeReference("Landroidx/appcompat/app/AlertDialog\$Builder;"))
        instrs += BuilderInstruction35c(
            Opcode.INVOKE_DIRECT, 2, v0, p0, 0, 0, 0,
            ImmutableMethodReference(
                "Landroidx/appcompat/app/AlertDialog\$Builder;", "<init>",
                listOf("Landroid/content/Context;"), "V"))

        // setTitle
        instrs += BuilderInstruction21c(Opcode.CONST_STRING, v1,
            ImmutableStringReference(cfg.title))
        instrs += BuilderInstruction35c(
            Opcode.INVOKE_VIRTUAL, 2, v0, v1, 0, 0, 0,
            ImmutableMethodReference(
                "Landroidx/appcompat/app/AlertDialog\$Builder;", "setTitle",
                listOf("Ljava/lang/CharSequence;"),
                "Landroidx/appcompat/app/AlertDialog\$Builder;"))
        instrs += BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v0)

        // setMessage
        instrs += BuilderInstruction21c(Opcode.CONST_STRING, v1,
            ImmutableStringReference(cfg.description))
        instrs += BuilderInstruction35c(
            Opcode.INVOKE_VIRTUAL, 2, v0, v1, 0, 0, 0,
            ImmutableMethodReference(
                "Landroidx/appcompat/app/AlertDialog\$Builder;", "setMessage",
                listOf("Ljava/lang/CharSequence;"),
                "Landroidx/appcompat/app/AlertDialog\$Builder;"))
        instrs += BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v0)

        // OK button — new Ok_id()
        instrs += BuilderInstruction21c(Opcode.CONST_STRING, v1,
            ImmutableStringReference(cfg.okText))
        instrs += BuilderInstruction21c(
            Opcode.NEW_INSTANCE, v2,
            ImmutableTypeReference("Lcom/zovex/injected/Ok_$id;"))
        instrs += BuilderInstruction35c(
            Opcode.INVOKE_DIRECT, 1, v2, 0, 0, 0, 0,
            ImmutableMethodReference("Lcom/zovex/injected/Ok_$id;", "<init>", emptyList(), "V"))
        instrs += BuilderInstruction35c(
            Opcode.INVOKE_VIRTUAL, 3, v0, v1, v2, 0, 0,
            ImmutableMethodReference(
                "Landroidx/appcompat/app/AlertDialog\$Builder;", "setPositiveButton",
                listOf("Ljava/lang/CharSequence;", "Landroid/content/DialogInterface\$OnClickListener;"),
                "Landroidx/appcompat/app/AlertDialog\$Builder;"))
        instrs += BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v0)

        // Telegram button (optional)
        if (cfg.telegramUrl.isNotBlank()) {
            instrs += BuilderInstruction21c(Opcode.CONST_STRING, v1,
                ImmutableStringReference("\u05d4\u05e6\u05d8\u05e8\u05e4\u05d5 \u05dc\u05d8\u05dc\u05d2\u05e8\u05dd"))
            instrs += BuilderInstruction21c(
                Opcode.NEW_INSTANCE, v2,
                ImmutableTypeReference("Lcom/zovex/injected/Tg_$id;"))
            instrs += BuilderInstruction35c(
                Opcode.INVOKE_DIRECT, 2, v2, p0, 0, 0, 0,
                ImmutableMethodReference("Lcom/zovex/injected/Tg_$id;", "<init>",
                    listOf("Landroid/content/Context;"), "V"))
            instrs += BuilderInstruction35c(
                Opcode.INVOKE_VIRTUAL, 3, v0, v1, v2, 0, 0,
                ImmutableMethodReference(
                    "Landroidx/appcompat/app/AlertDialog\$Builder;", "setNeutralButton",
                    listOf("Ljava/lang/CharSequence;", "Landroid/content/DialogInterface\$OnClickListener;"),
                    "Landroidx/appcompat/app/AlertDialog\$Builder;"))
            instrs += BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v0)
        }

        // Dismiss button
        instrs += BuilderInstruction21c(Opcode.CONST_STRING, v1,
            ImmutableStringReference("\u05d0\u05dc \u05ea\u05e6\u05d9\u05d2 \u05e9\u05d5\u05d1"))
        instrs += BuilderInstruction21c(
            Opcode.NEW_INSTANCE, v2,
            ImmutableTypeReference("Lcom/zovex/injected/Dismiss_$id;"))
        instrs += BuilderInstruction35c(
            Opcode.INVOKE_DIRECT, 2, v2, p0, 0, 0, 0,
            ImmutableMethodReference("Lcom/zovex/injected/Dismiss_$id;", "<init>",
                listOf("Landroid/content/Context;"), "V"))
        instrs += BuilderInstruction35c(
            Opcode.INVOKE_VIRTUAL, 3, v0, v1, v2, 0, 0,
            ImmutableMethodReference(
                "Landroidx/appcompat/app/AlertDialog\$Builder;", "setNegativeButton",
                listOf("Ljava/lang/CharSequence;", "Landroid/content/DialogInterface\$OnClickListener;"),
                "Landroidx/appcompat/app/AlertDialog\$Builder;"))
        instrs += BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v0)

        // setCancelable(false)
        instrs += BuilderInstruction11n(Opcode.CONST_4, v1, 0)
        instrs += BuilderInstruction35c(
            Opcode.INVOKE_VIRTUAL, 2, v0, v1, 0, 0, 0,
            ImmutableMethodReference(
                "Landroidx/appcompat/app/AlertDialog\$Builder;", "setCancelable",
                listOf("Z"), "Landroidx/appcompat/app/AlertDialog\$Builder;"))
        instrs += BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, v0)

        // show()
        instrs += BuilderInstruction35c(
            Opcode.INVOKE_VIRTUAL, 1, v0, 0, 0, 0, 0,
            ImmutableMethodReference(
                "Landroidx/appcompat/app/AlertDialog\$Builder;", "show",
                emptyList(), "Landroidx/appcompat/app/AlertDialog;"))

        // end label
        instrs += BuilderInstruction10x(Opcode.NOP).also {
            // attach end label
        }

        return instrs
    }

    // ── Build dialog helper classes ────────────────────────────

    private fun buildDialogClasses(cfg: Config): List<ClassDef> {
        val id = cfg.prefKey.replace(Regex("[^A-Za-z0-9]"), "_")
        val classes = mutableListOf<ClassDef>()

        // Ok class — סוגר דיאלוג
        classes += buildSimpleListenerClass("Lcom/zovex/injected/Ok_$id;")

        // Dismiss class — שומר ב-SharedPreferences ולא מציג שוב
        classes += buildDismissListenerClass("Lcom/zovex/injected/Dismiss_$id;", id)

        // Telegram class (optional)
        if (cfg.telegramUrl.isNotBlank()) {
            classes += buildTelegramListenerClass("Lcom/zovex/injected/Tg_$id;", cfg.telegramUrl)
        }

        return classes
    }

    private fun buildSimpleListenerClass(type: String): ClassDef {
        val onClick = ImmutableMethod(
            type, "onClick",
            listOf(
                ImmutableMethodParameter("Landroid/content/DialogInterface;", null, null),
                ImmutableMethodParameter("I", null, null)
            ), "V",
            AccessFlags.PUBLIC.value, null,
            ImmutableMethodImplementation(2, listOf(
                BuilderInstruction35c(Opcode.INVOKE_INTERFACE, 1, 1, 0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/content/DialogInterface;", "dismiss", emptyList(), "V")),
                BuilderInstruction10x(Opcode.RETURN_VOID)
            ), null, null)
        )

        val init = buildDefaultInit(type)

        return ImmutableClassDef(
            type, AccessFlags.PUBLIC.value,
            "Ljava/lang/Object;",
            listOf("Landroid/content/DialogInterface\$OnClickListener;"),
            null, null, null, null,
            listOf(init, onClick)
        )
    }

    private fun buildDismissListenerClass(type: String, id: String): ClassDef {
        val ctxField = com.android.tools.smali.dexlib2.immutable.ImmutableField(
            type, "ctx", "Landroid/content/Context;",
            AccessFlags.PRIVATE.value, null, null, null)

        val init = ImmutableMethod(
            type, "<init>",
            listOf(ImmutableMethodParameter("Landroid/content/Context;", null, null)),
            "V", AccessFlags.PUBLIC.value or AccessFlags.CONSTRUCTOR.value, null,
            ImmutableMethodImplementation(2, listOf(
                BuilderInstruction35c(Opcode.INVOKE_DIRECT, 1, 0, 0, 0, 0, 0,
                    ImmutableMethodReference("Ljava/lang/Object;", "<init>", emptyList(), "V")),
                BuilderInstruction22c(Opcode.IPUT_OBJECT, 1, 0,
                    ImmutableFieldReference(type, "ctx", "Landroid/content/Context;")),
                BuilderInstruction10x(Opcode.RETURN_VOID)
            ), null, null)
        )

        val onClick = ImmutableMethod(
            type, "onClick",
            listOf(
                ImmutableMethodParameter("Landroid/content/DialogInterface;", null, null),
                ImmutableMethodParameter("I", null, null)
            ), "V", AccessFlags.PUBLIC.value, null,
            ImmutableMethodImplementation(4, listOf(
                // get ctx
                BuilderInstruction22c(Opcode.IGET_OBJECT, 0, 2,
                    ImmutableFieldReference(type, "ctx", "Landroid/content/Context;")),
                // getSharedPreferences
                BuilderInstruction21c(Opcode.CONST_STRING, 1,
                    ImmutableStringReference("zovex_pref_$id")),
                BuilderInstruction11n(Opcode.CONST_4, 2, 0),
                BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 3, 0, 1, 2, 0, 0,
                    ImmutableMethodReference("Landroid/content/Context;", "getSharedPreferences",
                        listOf("Ljava/lang/String;", "I"), "Landroid/content/SharedPreferences;")),
                BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0),
                // edit()
                BuilderInstruction35c(Opcode.INVOKE_INTERFACE, 1, 0, 0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/content/SharedPreferences;", "edit",
                        emptyList(), "Landroid/content/SharedPreferences\$Editor;")),
                BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0),
                // putBoolean
                BuilderInstruction21c(Opcode.CONST_STRING, 1,
                    ImmutableStringReference("dismissed_$id")),
                BuilderInstruction11n(Opcode.CONST_4, 2, 1),
                BuilderInstruction35c(Opcode.INVOKE_INTERFACE, 3, 0, 1, 2, 0, 0,
                    ImmutableMethodReference("Landroid/content/SharedPreferences\$Editor;",
                        "putBoolean", listOf("Ljava/lang/String;", "Z"),
                        "Landroid/content/SharedPreferences\$Editor;")),
                BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0),
                // apply()
                BuilderInstruction35c(Opcode.INVOKE_INTERFACE, 1, 0, 0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/content/SharedPreferences\$Editor;",
                        "apply", emptyList(), "V")),
                // dismiss
                BuilderInstruction35c(Opcode.INVOKE_INTERFACE, 1, 3, 0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/content/DialogInterface;", "dismiss", emptyList(), "V")),
                BuilderInstruction10x(Opcode.RETURN_VOID)
            ), null, null)
        )

        return ImmutableClassDef(
            type, AccessFlags.PUBLIC.value, "Ljava/lang/Object;",
            listOf("Landroid/content/DialogInterface\$OnClickListener;"),
            null, null, null, listOf(ctxField),
            listOf(init, onClick)
        )
    }

    private fun buildTelegramListenerClass(type: String, url: String): ClassDef {
        val ctxField = com.android.tools.smali.dexlib2.immutable.ImmutableField(
            type, "ctx", "Landroid/content/Context;",
            AccessFlags.PRIVATE.value, null, null, null)

        val init = ImmutableMethod(
            type, "<init>",
            listOf(ImmutableMethodParameter("Landroid/content/Context;", null, null)),
            "V", AccessFlags.PUBLIC.value or AccessFlags.CONSTRUCTOR.value, null,
            ImmutableMethodImplementation(2, listOf(
                BuilderInstruction35c(Opcode.INVOKE_DIRECT, 1, 0, 0, 0, 0, 0,
                    ImmutableMethodReference("Ljava/lang/Object;", "<init>", emptyList(), "V")),
                BuilderInstruction22c(Opcode.IPUT_OBJECT, 1, 0,
                    ImmutableFieldReference(type, "ctx", "Landroid/content/Context;")),
                BuilderInstruction10x(Opcode.RETURN_VOID)
            ), null, null)
        )

        val onClick = ImmutableMethod(
            type, "onClick",
            listOf(
                ImmutableMethodParameter("Landroid/content/DialogInterface;", null, null),
                ImmutableMethodParameter("I", null, null)
            ), "V", AccessFlags.PUBLIC.value, null,
            ImmutableMethodImplementation(4, listOf(
                BuilderInstruction22c(Opcode.IGET_OBJECT, 0, 2,
                    ImmutableFieldReference(type, "ctx", "Landroid/content/Context;")),
                BuilderInstruction21c(Opcode.CONST_STRING, 1, ImmutableStringReference(url)),
                BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 1, 0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/net/Uri;", "parse",
                        listOf("Ljava/lang/String;"), "Landroid/net/Uri;")),
                BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1),
                BuilderInstruction21c(Opcode.NEW_INSTANCE, 2,
                    ImmutableTypeReference("Landroid/content/Intent;")),
                BuilderInstruction21c(Opcode.CONST_STRING, 3,
                    ImmutableStringReference("android.intent.action.VIEW")),
                BuilderInstruction35c(Opcode.INVOKE_DIRECT, 3, 2, 3, 1, 0, 0,
                    ImmutableMethodReference("Landroid/content/Intent;", "<init>",
                        listOf("Ljava/lang/String;", "Landroid/net/Uri;"), "V")),
                BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 2, 0, 2, 0, 0, 0,
                    ImmutableMethodReference("Landroid/content/Context;", "startActivity",
                        listOf("Landroid/content/Intent;"), "V")),
                BuilderInstruction35c(Opcode.INVOKE_INTERFACE, 1, 3, 0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/content/DialogInterface;", "dismiss", emptyList(), "V")),
                BuilderInstruction10x(Opcode.RETURN_VOID)
            ), null, null)
        )

        return ImmutableClassDef(
            type, AccessFlags.PUBLIC.value, "Ljava/lang/Object;",
            listOf("Landroid/content/DialogInterface\$OnClickListener;"),
            null, null, null, listOf(ctxField),
            listOf(init, onClick)
        )
    }

    private fun buildDefaultInit(type: String) = ImmutableMethod(
        type, "<init>", emptyList(), "V",
        AccessFlags.PUBLIC.value or AccessFlags.CONSTRUCTOR.value, null,
        ImmutableMethodImplementation(1, listOf(
            BuilderInstruction35c(Opcode.INVOKE_DIRECT, 1, 0, 0, 0, 0, 0,
                ImmutableMethodReference("Ljava/lang/Object;", "<init>", emptyList(), "V")),
            BuilderInstruction10x(Opcode.RETURN_VOID)
        ), null, null)
    )

    // ── Remove dialogs ─────────────────────────────────────────

    private fun removeDialogFromClass(cls: ClassDef): ClassDef {
        val newMethods = cls.methods.map { method ->
            val impl = method.implementation ?: return@map method
            val hasDialog = impl.instructions.any { instr ->
                instr.opcode == Opcode.INVOKE_VIRTUAL &&
                (instr as? ReferenceInstruction)?.reference?.toString()?.contains("AlertDialog") == true
            }
            if (!hasDialog) return@map method

            // מצא ה-show() וסיים את ה-method לפניו
            val instrs = impl.instructions.toMutableList()
            val showIdx = instrs.indexOfFirst { instr ->
                instr.opcode == Opcode.INVOKE_VIRTUAL &&
                (instr as? ReferenceInstruction)?.reference?.toString()?.contains("->show()") == true
            }

            if (showIdx <= 0) return@map method

            // החלף ב-return-void בתחילת המethod
            val newInstrs = listOf(BuilderInstruction10x(Opcode.RETURN_VOID)) +
                instrs.drop(showIdx + 1)

            ImmutableMethod(
                method.definingClass, method.name,
                method.parameters, method.returnType,
                method.accessFlags, method.annotations,
                ImmutableMethodImplementation(
                    impl.registerCount,
                    newInstrs,
                    impl.tryBlocks,
                    impl.debugItems
                )
            )
        }

        return ImmutableClassDef(
            cls.type, cls.accessFlags, cls.superclass,
            cls.interfaces, cls.sourceFile,
            cls.annotations, cls.staticFields,
            cls.instanceFields, newMethods
        )
    }

    // ── Write DEX ──────────────────────────────────────────────

    private fun writeDex(classes: List<ClassDef>, outFile: File, opcodes: Opcodes) {
        val pool = DexPool(opcodes)
        for (cls in classes) pool.internClass(cls)
        pool.writeTo(FileDataStore(outFile))
    }

    // ── Immutable references ───────────────────────────────────

    private fun ImmutableStringReference(s: String) =
        com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference(s)

    private fun ImmutableTypeReference(s: String) =
        com.android.tools.smali.dexlib2.immutable.reference.ImmutableTypeReference(s)

    private fun ImmutableMethodReference(
        cls: String, name: String, params: List<String>, ret: String
    ) = com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference(
        cls, name, params, ret)

    private fun ImmutableFieldReference(cls: String, name: String, type: String) =
        com.android.tools.smali.dexlib2.immutable.reference.ImmutableFieldReference(cls, name, type)

    private fun ImmutableMethodParameter(type: String, ann: Any?, name: String?) =
        com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter(type, null, name)
}

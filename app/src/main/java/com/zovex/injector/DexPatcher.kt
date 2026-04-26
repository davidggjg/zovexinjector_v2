package com.zovex.injector

import android.util.Log
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.DexFileFactory
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.builder.*
import com.android.tools.smali.dexlib2.builder.instruction.*
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.Method
import com.android.tools.smali.dexlib2.iface.reference.FieldReference
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.android.tools.smali.dexlib2.iface.reference.TypeReference
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter
import com.android.tools.smali.dexlib2.immutable.ImmutableField
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

    // ---------- public API ----------
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
                instr.opcode == com.android.tools.smali.dexlib2.Opcode.INVOKE_VIRTUAL &&
                        (instr as? BuilderInstruction35c)?.reference?.toString()?.contains("AlertDialog") == true
            } == true
        }
    }

    // ---------- patching ----------
    private fun patchClass(cls: ClassDef, cfg: Config): ClassDef {
        val newMethods = cls.methods.map { method ->
            if (method.name == "onCreate" && method.parameterTypes.firstOrNull() == "Landroid/os/Bundle;") {
                patchOnCreate(method, cls.type, cfg)
            } else method
        }

        // ImmutableClassDef expects List/Set/SortedSet – convert accordingly
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

        // Find insertion point (after super.onCreate or setContentView)
        var insertIndex = 0
        for ((idx, instr) in impl.instructions.withIndex()) {
            if (instr.opcode == com.android.tools.smali.dexlib2.Opcode.INVOKE_SUPER ||
                instr.opcode == com.android.tools.smali.dexlib2.Opcode.INVOKE_VIRTUAL) {
                val ref = (instr as? BuilderInstruction35c)?.reference?.toString() ?: continue
                if ("onCreate(Landroid/os/Bundle;)V" in ref || "setContentView" in ref) {
                    insertIndex = idx + 1
                    break
                }
            }
        }

        // Build the instructions
        val dialogInstrs = buildDialogInstructions(cfg, id, classType, mutableImpl.registerCount)
        val endLabel = mutableImpl.newLabel()

        // Add all instructions + the label at the end
        for (instr in dialogInstrs) {
            mutableImpl.addInstruction(insertIndex, instr)
            insertIndex++
        }
        mutableImpl.addInstructionAtLocation(insertIndex, BuilderInstruction10x(com.android.tools.smali.dexlib2.Opcode.NOP))
        mutableImpl.addLabelAtLocation(endLabel, insertIndex)

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

    // ---------- build dialog instructions ----------
    private fun buildDialogInstructions(
        cfg: Config, id: String, classType: String, baseReg: Int
    ): List<BuilderInstruction> {
        val v0 = baseReg       // temporary
        val v1 = baseReg + 1
        val v2 = baseReg + 2
        val p0 = 0             // "this" register in method

        val instrs = mutableListOf<BuilderInstruction>()

        // ---- SharedPreferences check ----
        instrs += BuilderInstruction21c(
            com.android.tools.smali.dexlib2.Opcode.CONST_STRING, v1,
            ImmutableStringReference("zovex_pref_$id")
        )
        instrs += BuilderInstruction11n(com.android.tools.smali.dexlib2.Opcode.CONST_4, v2, 0)
        instrs += BuilderInstruction35c(
            com.android.tools.smali.dexlib2.Opcode.INVOKE_VIRTUAL, 3, p0, v1, v2, 0, 0,
            ImmutableMethodReference(
                "Landroid/app/Activity;", "getSharedPreferences",
                listOf("Ljava/lang/String;", "I"), "Landroid/content/SharedPreferences;")
        )
        instrs += BuilderInstruction11x(com.android.tools.smali.dexlib2.Opcode.MOVE_RESULT_OBJECT, v0)
        instrs += BuilderInstruction21c(
            com.android.tools.smali.dexlib2.Opcode.CONST_STRING, v1,
            ImmutableStringReference("dismissed_$id")
        )
        instrs += BuilderInstruction11n(com.android.tools.smali.dexlib2.Opcode.CONST_4, v2, 0)
        instrs += BuilderInstruction35c(
            com.android.tools.smali.dexlib2.Opcode.INVOKE_INTERFACE, 3, v0, v1, v2, 0, 0,
            ImmutableMethodReference(
                "Landroid/content/SharedPreferences;", "getBoolean",
                listOf("Ljava/lang/String;", "Z"), "Z")
        )
        instrs += BuilderInstruction11x(com.android.tools.smali.dexlib2.Opcode.MOVE_RESULT, v1)

        // if-nez v1, skip dialog (label will be attached later)
        val skipLabel = Label()
        instrs += BuilderInstruction21t(com.android.tools.smali.dexlib2.Opcode.IF_NEZ, v1, skipLabel)

        // ---- Build dialog ----
        instrs += BuilderInstruction21c(
            com.android.tools.smali.dexlib2.Opcode.NEW_INSTANCE, v0,
            ImmutableTypeReference("Landroidx/appcompat/app/AlertDialog\$Builder;")
        )
        instrs += BuilderInstruction35c(
            com.android.tools.smali.dexlib2.Opcode.INVOKE_DIRECT, 2, v0, p0, 0, 0, 0,
            ImmutableMethodReference(
                "Landroidx/appcompat/app/AlertDialog\$Builder;", "<init>",
                listOf("Landroid/content/Context;"), "V")
        )

        // setTitle
        instrs += BuilderInstruction21c(com.android.tools.smali.dexlib2.Opcode.CONST_STRING, v1,
            ImmutableStringReference(cfg.title))
        instrs += BuilderInstruction35c(
            com.android.tools.smali.dexlib2.Opcode.INVOKE_VIRTUAL, 2, v0, v1, 0, 0, 0,
            ImmutableMethodReference(
                "Landroidx/appcompat/app/AlertDialog\$Builder;", "setTitle",
                listOf("Ljava/lang/CharSequence;"), "Landroidx/appcompat/app/AlertDialog\$Builder;")
        )
        instrs += BuilderInstruction11x(com.android.tools.smali.dexlib2.Opcode.MOVE_RESULT_OBJECT, v0)

        // setMessage
        instrs += BuilderInstruction21c(com.android.tools.smali.dexlib2.Opcode.CONST_STRING, v1,
            ImmutableStringReference(cfg.description))
        instrs += BuilderInstruction35c(
            com.android.tools.smali.dexlib2.Opcode.INVOKE_VIRTUAL, 2, v0, v1, 0, 0, 0,
            ImmutableMethodReference(
                "Landroidx/appcompat/app/AlertDialog\$Builder;", "setMessage",
                listOf("Ljava/lang/CharSequence;"), "Landroidx/appcompat/app/AlertDialog\$Builder;")
        )
        instrs += BuilderInstruction11x(com.android.tools.smali.dexlib2.Opcode.MOVE_RESULT_OBJECT, v0)

        // OK button
        instrs += BuilderInstruction21c(com.android.tools.smali.dexlib2.Opcode.CONST_STRING, v1,
            ImmutableStringReference(cfg.okText))
        instrs += BuilderInstruction21c(
            com.android.tools.smali.dexlib2.Opcode.NEW_INSTANCE, v2,
            ImmutableTypeReference("Lcom/zovex/injected/Ok_$id;")
        )
        instrs += BuilderInstruction35c(
            com.android.tools.smali.dexlib2.Opcode.INVOKE_DIRECT, 1, v2, 0, 0, 0, 0,
            ImmutableMethodReference("Lcom/zovex/injected/Ok_$id;", "<init>", emptyList(), "V")
        )
        instrs += BuilderInstruction35c(
            com.android.tools.smali.dexlib2.Opcode.INVOKE_VIRTUAL, 3, v0, v1, v2, 0, 0,
            ImmutableMethodReference(
                "Landroidx/appcompat/app/AlertDialog\$Builder;", "setPositiveButton",
                listOf("Ljava/lang/CharSequence;", "Landroid/content/DialogInterface\$OnClickListener;"),
                "Landroidx/appcompat/app/AlertDialog\$Builder;")
        )
        instrs += BuilderInstruction11x(com.android.tools.smali.dexlib2.Opcode.MOVE_RESULT_OBJECT, v0)

        // Telegram button (optional)
        if (cfg.telegramUrl.isNotBlank()) {
            instrs += BuilderInstruction21c(com.android.tools.smali.dexlib2.Opcode.CONST_STRING, v1,
                ImmutableStringReference("הצטרפו לטלגרם"))
            instrs += BuilderInstruction21c(
                com.android.tools.smali.dexlib2.Opcode.NEW_INSTANCE, v2,
                ImmutableTypeReference("Lcom/zovex/injected/Tg_$id;")
            )
            instrs += BuilderInstruction35c(
                com.android.tools.smali.dexlib2.Opcode.INVOKE_DIRECT, 2, v2, p0, 0, 0, 0,
                ImmutableMethodReference("Lcom/zovex/injected/Tg_$id;", "<init>",
                    listOf("Landroid/content/Context;"), "V")
            )
            instrs += BuilderInstruction35c(
                com.android.tools.smali.dexlib2.Opcode.INVOKE_VIRTUAL, 3, v0, v1, v2, 0, 0,
                ImmutableMethodReference(
                    "Landroidx/appcompat/app/AlertDialog\$Builder;", "setNeutralButton",
                    listOf("Ljava/lang/CharSequence;", "Landroid/content/DialogInterface\$OnClickListener;"),
                    "Landroidx/appcompat/app/AlertDialog\$Builder;")
            )
            instrs += BuilderInstruction11x(com.android.tools.smali.dexlib2.Opcode.MOVE_RESULT_OBJECT, v0)
        }

        // Dismiss button
        instrs += BuilderInstruction21c(com.android.tools.smali.dexlib2.Opcode.CONST_STRING, v1,
            ImmutableStringReference("אל תציג שוב"))
        instrs += BuilderInstruction21c(
            com.android.tools.smali.dexlib2.Opcode.NEW_INSTANCE, v2,
            ImmutableTypeReference("Lcom/zovex/injected/Dismiss_$id;")
        )
        instrs += BuilderInstruction35c(
            com.android.tools.smali.dexlib2.Opcode.INVOKE_DIRECT, 2, v2, p0, 0, 0, 0,
            ImmutableMethodReference("Lcom/zovex/injected/Dismiss_$id;", "<init>",
                listOf("Landroid/content/Context;"), "V")
        )
        instrs += BuilderInstruction35c(
            com.android.tools.smali.dexlib2.Opcode.INVOKE_VIRTUAL, 3, v0, v1, v2, 0, 0,
            ImmutableMethodReference(
                "Landroidx/appcompat/app/AlertDialog\$Builder;", "setNegativeButton",
                listOf("Ljava/lang/CharSequence;", "Landroid/content/DialogInterface\$OnClickListener;"),
                "Landroidx/appcompat/app/AlertDialog\$Builder;")
        )
        instrs += BuilderInstruction11x(com.android.tools.smali.dexlib2.Opcode.MOVE_RESULT_OBJECT, v0)

        // setCancelable(false)
        instrs += BuilderInstruction11n(com.android.tools.smali.dexlib2.Opcode.CONST_4, v1, 0)
        instrs += BuilderInstruction35c(
            com.android.tools.smali.dexlib2.Opcode.INVOKE_VIRTUAL, 2, v0, v1, 0, 0, 0,
            ImmutableMethodReference(
                "Landroidx/appcompat/app/AlertDialog\$Builder;", "setCancelable",
                listOf("Z"), "Landroidx/appcompat/app/AlertDialog\$Builder;")
        )
        instrs += BuilderInstruction11x(com.android.tools.smali.dexlib2.Opcode.MOVE_RESULT_OBJECT, v0)

        // show()
        instrs += BuilderInstruction35c(
            com.android.tools.smali.dexlib2.Opcode.INVOKE_VIRTUAL, 1, v0, 0, 0, 0, 0,
            ImmutableMethodReference(
                "Landroidx/appcompat/app/AlertDialog\$Builder;", "show",
                emptyList(), "Landroidx/appcompat/app/AlertDialog;")
        )

        // Placeholder for skip label – it will be resolved when adding to MutableMethodImplementation
        // We'll return the list; the caller will attach the label.
        return instrs
    }

    // ---------- dialog helper classes ----------
    private fun buildDialogClasses(cfg: Config): List<ClassDef> {
        val id = cfg.prefKey.replace(Regex("[^A-Za-z0-9]"), "_")
        val classes = mutableListOf<ClassDef>()

        classes += buildOkListenerClass("Lcom/zovex/injected/Ok_$id;")
        classes += buildDismissListenerClass("Lcom/zovex/injected/Dismiss_$id;", id)
        if (cfg.telegramUrl.isNotBlank()) {
            classes += buildTelegramListenerClass("Lcom/zovex/injected/Tg_$id;", cfg.telegramUrl)
        }
        return classes
    }

    private fun buildOkListenerClass(type: String): ClassDef {
        val onClick = ImmutableMethod(
            type, "onClick",
            listOf(
                ImmutableMethodParameter("Landroid/content/DialogInterface;", null, null),
                ImmutableMethodParameter("I", null, null)
            ), "V",
            AccessFlags.PUBLIC.value, null,
            ImmutableMethodImplementation(2, listOf(
                BuilderInstruction35c(com.android.tools.smali.dexlib2.Opcode.INVOKE_INTERFACE, 1, 1, 0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/content/DialogInterface;", "dismiss", emptyList(), "V")),
                BuilderInstruction10x(com.android.tools.smali.dexlib2.Opcode.RETURN_VOID)
            ), null, null)
        )

        val init = defaultInit(type)

        return ImmutableClassDef(
            type, AccessFlags.PUBLIC.value, "Ljava/lang/Object;",
            listOf("Landroid/content/DialogInterface\$OnClickListener;"),
            null, emptySet(), emptyList(), emptyList(),
            listOf(init, onClick)
        )
    }

    private fun buildDismissListenerClass(type: String, id: String): ClassDef {
        val ctxField = ImmutableField(
            type, "ctx", "Landroid/content/Context;",
            AccessFlags.PRIVATE.value, null, null, null
        )

        val init = ImmutableMethod(
            type, "<init>",
            listOf(ImmutableMethodParameter("Landroid/content/Context;", null, null)),
            "V", AccessFlags.PUBLIC.value or AccessFlags.CONSTRUCTOR.value, null,
            ImmutableMethodImplementation(2, listOf(
                BuilderInstruction35c(com.android.tools.smali.dexlib2.Opcode.INVOKE_DIRECT, 1, 0, 0, 0, 0, 0,
                    ImmutableMethodReference("Ljava/lang/Object;", "<init>", emptyList(), "V")),
                BuilderInstruction22c(com.android.tools.smali.dexlib2.Opcode.IPUT_OBJECT, 1, 0,
                    ImmutableFieldReference(type, "ctx", "Landroid/content/Context;")),
                BuilderInstruction10x(com.android.tools.smali.dexlib2.Opcode.RETURN_VOID)
            ), null, null)
        )

        val onClick = ImmutableMethod(
            type, "onClick",
            listOf(
                ImmutableMethodParameter("Landroid/content/DialogInterface;", null, null),
                ImmutableMethodParameter("I", null, null)
            ), "V", AccessFlags.PUBLIC.value, null,
            ImmutableMethodImplementation(5, listOf(
                BuilderInstruction22c(com.android.tools.smali.dexlib2.Opcode.IGET_OBJECT, 0, 2,
                    ImmutableFieldReference(type, "ctx", "Landroid/content/Context;")),
                BuilderInstruction21c(com.android.tools.smali.dexlib2.Opcode.CONST_STRING, 1,
                    ImmutableStringReference("zovex_pref_$id")),
                BuilderInstruction11n(com.android.tools.smali.dexlib2.Opcode.CONST_4, 2, 0),
                BuilderInstruction35c(com.android.tools.smali.dexlib2.Opcode.INVOKE_VIRTUAL, 3, 0, 1, 2, 0, 0,
                    ImmutableMethodReference("Landroid/content/Context;", "getSharedPreferences",
                        listOf("Ljava/lang/String;", "I"), "Landroid/content/SharedPreferences;")),
                BuilderInstruction11x(com.android.tools.smali.dexlib2.Opcode.MOVE_RESULT_OBJECT, 0),
                BuilderInstruction35c(com.android.tools.smali.dexlib2.Opcode.INVOKE_INTERFACE, 1, 0, 0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/content/SharedPreferences;", "edit",
                        emptyList(), "Landroid/content/SharedPreferences\$Editor;")),
                BuilderInstruction11x(com.android.tools.smali.dexlib2.Opcode.MOVE_RESULT_OBJECT, 0),
                BuilderInstruction21c(com.android.tools.smali.dexlib2.Opcode.CONST_STRING, 1,
                    ImmutableStringReference("dismissed_$id")),
                BuilderInstruction11n(com.android.tools.smali.dexlib2.Opcode.CONST_4, 2, 1),
                BuilderInstruction35c(com.android.tools.smali.dexlib2.Opcode.INVOKE_INTERFACE, 3, 0, 1, 2, 0, 0,
                    ImmutableMethodReference("Landroid/content/SharedPreferences\$Editor;",
                        "putBoolean", listOf("Ljava/lang/String;", "Z"),
                        "Landroid/content/SharedPreferences\$Editor;")),
                BuilderInstruction11x(com.android.tools.smali.dexlib2.Opcode.MOVE_RESULT_OBJECT, 0),
                BuilderInstruction35c(com.android.tools.smali.dexlib2.Opcode.INVOKE_INTERFACE, 1, 0, 0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/content/SharedPreferences\$Editor;",
                        "apply", emptyList(), "V")),
                BuilderInstruction35c(com.android.tools.smali.dexlib2.Opcode.INVOKE_INTERFACE, 1, 3, 0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/content/DialogInterface;", "dismiss", emptyList(), "V")),
                BuilderInstruction10x(com.android.tools.smali.dexlib2.Opcode.RETURN_VOID)
            ), null, null)
        )

        return ImmutableClassDef(
            type, AccessFlags.PUBLIC.value, "Ljava/lang/Object;",
            listOf("Landroid/content/DialogInterface\$OnClickListener;"),
            null, emptySet(), emptyList(), listOf(ctxField),
            listOf(init, onClick)
        )
    }

    private fun buildTelegramListenerClass(type: String, url: String): ClassDef {
        val ctxField = ImmutableField(
            type, "ctx", "Landroid/content/Context;",
            AccessFlags.PRIVATE.value, null, null, null
        )

        val init = ImmutableMethod(
            type, "<init>",
            listOf(ImmutableMethodParameter("Landroid/content/Context;", null, null)),
            "V", AccessFlags.PUBLIC.value or AccessFlags.CONSTRUCTOR.value, null,
            ImmutableMethodImplementation(2, listOf(
                BuilderInstruction35c(com.android.tools.smali.dexlib2.Opcode.INVOKE_DIRECT, 1, 0, 0, 0, 0, 0,
                    ImmutableMethodReference("Ljava/lang/Object;", "<init>", emptyList(), "V")),
                BuilderInstruction22c(com.android.tools.smali.dexlib2.Opcode.IPUT_OBJECT, 1, 0,
                    ImmutableFieldReference(type, "ctx", "Landroid/content/Context;")),
                BuilderInstruction10x(com.android.tools.smali.dexlib2.Opcode.RETURN_VOID)
            ), null, null)
        )

        val onClick = ImmutableMethod(
            type, "onClick",
            listOf(
                ImmutableMethodParameter("Landroid/content/DialogInterface;", null, null),
                ImmutableMethodParameter("I", null, null)
            ), "V", AccessFlags.PUBLIC.value, null,
            ImmutableMethodImplementation(6, listOf(
                BuilderInstruction22c(com.android.tools.smali.dexlib2.Opcode.IGET_OBJECT, 0, 2,
                    ImmutableFieldReference(type, "ctx", "Landroid/content/Context;")),
                BuilderInstruction21c(com.android.tools.smali.dexlib2.Opcode.CONST_STRING, 1,
                    ImmutableStringReference(url)),
                BuilderInstruction35c(com.android.tools.smali.dexlib2.Opcode.INVOKE_STATIC, 1, 1, 0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/net/Uri;", "parse",
                        listOf("Ljava/lang/String;"), "Landroid/net/Uri;")),
                BuilderInstruction11x(com.android.tools.smali.dexlib2.Opcode.MOVE_RESULT_OBJECT, 1),
                BuilderInstruction21c(com.android.tools.smali.dexlib2.Opcode.NEW_INSTANCE, 2,
                    ImmutableTypeReference("Landroid/content/Intent;")),
                BuilderInstruction21c(com.android.tools.smali.dexlib2.Opcode.CONST_STRING, 3,
                    ImmutableStringReference("android.intent.action.VIEW")),
                BuilderInstruction35c(com.android.tools.smali.dexlib2.Opcode.INVOKE_DIRECT, 3, 2, 3, 1, 0, 0,
                    ImmutableMethodReference("Landroid/content/Intent;", "<init>",
                        listOf("Ljava/lang/String;", "Landroid/net/Uri;"), "V")),
                BuilderInstruction35c(com.android.tools.smali.dexlib2.Opcode.INVOKE_VIRTUAL, 2, 0, 2, 0, 0, 0,
                    ImmutableMethodReference("Landroid/content/Context;", "startActivity",
                        listOf("Landroid/content/Intent;"), "V")),
                BuilderInstruction35c(com.android.tools.smali.dexlib2.Opcode.INVOKE_INTERFACE, 1, 4, 0, 0, 0, 0,
                    ImmutableMethodReference("Landroid/content/DialogInterface;", "dismiss", emptyList(), "V")),
                BuilderInstruction10x(com.android.tools.smali.dexlib2.Opcode.RETURN_VOID)
            ), null, null)
        )

        return ImmutableClassDef(
            type, AccessFlags.PUBLIC.value, "Ljava/lang/Object;",
            listOf("Landroid/content/DialogInterface\$OnClickListener;"),
            null, emptySet(), emptyList(), listOf(ctxField),
            listOf(init, onClick)
        )
    }

    private fun defaultInit(type: String) = ImmutableMethod(
        type, "<init>", emptyList(), "V",
        AccessFlags.PUBLIC.value or AccessFlags.CONSTRUCTOR.value, null,
        ImmutableMethodImplementation(1, listOf(
            BuilderInstruction35c(com.android.tools.smali.dexlib2.Opcode.INVOKE_DIRECT, 1, 0, 0, 0, 0, 0,
                ImmutableMethodReference("Ljava/lang/Object;", "<init>", emptyList(), "V")),
            BuilderInstruction10x(com.android.tools.smali.dexlib2.Opcode.RETURN_VOID)
        ), null, null)
    )

    // ---------- remove dialogs ----------
    private fun removeDialogFromClass(cls: ClassDef): ClassDef {
        val newMethods = cls.methods.map { method ->
            val impl = method.implementation ?: return@map method
            val instrs = impl.instructions.toList()
            val showIndex = instrs.indexOfFirst { instr ->
                instr.opcode == com.android.tools.smali.dexlib2.Opcode.INVOKE_VIRTUAL &&
                        (instr as? BuilderInstruction35c)?.reference?.toString()?.contains("->show()") == true
            }
            if (showIndex == -1) return@map method

            // Replace with empty method that does nothing (return-void)
            val newImpl = ImmutableMethodImplementation(
                impl.registerCount,
                listOf(BuilderInstruction10x(com.android.tools.smali.dexlib2.Opcode.RETURN_VOID)),
                emptyList(), emptyList()
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

    // ---------- write DEX ----------
    private fun writeDex(classes: List<ClassDef>, outFile: File, opcodes: Opcodes) {
        val pool = DexPool(opcodes)
        for (cls in classes) pool.internClass(cls)
        pool.writeTo(FileDataStore(outFile))
    }
}

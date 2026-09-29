using System.Buffers.Binary;

namespace ModScanner.Core;

/// <summary>Разбор байт-кода JVM на инструкции: коды операций и их операнды.</summary>
internal static class Bytecode
{
    public const byte NOP = 0, ACONST_NULL = 1, ICONST_M1 = 2, ICONST_0 = 3, ICONST_5 = 8, LCONST_0 = 9, LCONST_1 = 10,
        FCONST_0 = 11, DCONST_0 = 14, DCONST_1 = 15, BIPUSH = 16, SIPUSH = 17, LDC = 18, LDC_W = 19, LDC2_W = 20,
        ILOAD = 21, ALOAD = 25, AALOAD = 50, ISTORE = 54, ASTORE = 58, POP = 87, POP2 = 88, DUP = 89, DUP_X1 = 90, DUP_X2 = 91,
        DUP2 = 92, DUP2_X1 = 93, DUP2_X2 = 94, SWAP = 95, IADD = 96, IXOR = 130, LXOR = 131, IINC = 132,
        I2L = 133, L2I = 136, LCMP = 148, IFEQ = 153, IFNE = 154, IFLT = 155, IFGE = 156, IFGT = 157, IFLE = 158,
        IF_ICMPEQ = 159, IF_ICMPNE = 160, IF_ACMPEQ = 165, IF_ACMPNE = 166, GOTO = 167, JSR = 168, RET = 169,
        TABLESWITCH = 170, LOOKUPSWITCH = 171, IRETURN = 172, LRETURN = 173, FRETURN = 174, DRETURN = 175,
        ARETURN = 176, RETURN = 177, GETSTATIC = 178, PUTSTATIC = 179, GETFIELD = 180, PUTFIELD = 181,
        INVOKEVIRTUAL = 182, INVOKESPECIAL = 183, INVOKESTATIC = 184, INVOKEINTERFACE = 185, INVOKEDYNAMIC = 186,
        NEW = 187, NEWARRAY = 188, ANEWARRAY = 189, ARRAYLENGTH = 190, ATHROW = 191, CHECKCAST = 192,
        INSTANCEOF = 193, MONITORENTER = 194, MONITOREXIT = 195, WIDE = 196, MULTIANEWARRAY = 197,
        IFNULL = 198, IFNONNULL = 199, GOTO_W = 200, JSR_W = 201;

    // длина инструкции по коду операции (0 — переменная/особая)
    private static readonly byte[] Len = BuildLen();

    private static byte[] BuildLen()
    {
        var l = new byte[256];
        for (int i = 0; i < 256; i++) l[i] = 1;
        foreach (int op in new[] { BIPUSH, LDC, ILOAD, 22, 23, 24, ALOAD, ISTORE, 55, 56, 57, ASTORE, RET, NEWARRAY }) l[op] = 2;
        foreach (int op in new[] { SIPUSH, LDC_W, LDC2_W, IINC, IFEQ, IFNE, IFLT, IFGE, IFGT, IFLE, IF_ICMPEQ, IF_ICMPNE, 161, 162, 163, 164,
            IF_ACMPEQ, IF_ACMPNE, GOTO, JSR, GETSTATIC, PUTSTATIC, GETFIELD, PUTFIELD, INVOKEVIRTUAL, INVOKESPECIAL, INVOKESTATIC,
            NEW, ANEWARRAY, CHECKCAST, INSTANCEOF, IFNULL, IFNONNULL }) l[op] = 3;
        l[MULTIANEWARRAY] = 4;
        l[INVOKEINTERFACE] = 5; l[INVOKEDYNAMIC] = 5; l[GOTO_W] = 5; l[JSR_W] = 5;
        l[TABLESWITCH] = 0; l[LOOKUPSWITCH] = 0; l[WIDE] = 0;
        return l;
    }

    public static bool IsBranch(byte op) => (op >= IFEQ && op <= JSR) || op == IFNULL || op == IFNONNULL || op == GOTO_W || op == JSR_W;
    public static bool IsInvoke(byte op) => op >= INVOKEVIRTUAL && op <= INVOKEDYNAMIC;
    public static bool IsFieldAccess(byte op) => op >= GETSTATIC && op <= PUTFIELD;
    public static bool IsReturn(byte op) => op >= IRETURN && op <= RETURN;
    public static bool IsLdc(byte op) => op is LDC or LDC_W or LDC2_W;
    public static bool IsXor(byte op) => op is IXOR or LXOR;
    public static bool IsIntPush(byte op) => op is >= ICONST_M1 and <= ICONST_5 || op is BIPUSH or SIPUSH;

    public static List<Insn> Disassemble(byte[] code)
    {
        var list = new List<Insn>(code.Length / 3 + 1);
        int pc = 0;
        while (pc < code.Length)
        {
            byte op = code[pc];
            var ins = new Insn { Pc = pc, Op = op };
            int len = Len[op];
            switch (op)
            {
                case TABLESWITCH:
                {
                    int p = (pc + 4) & ~3;
                    if (p + 12 > code.Length) { ins.Len = code.Length - pc; list.Add(ins); return list; }
                    int def = BinaryPrimitives.ReadInt32BigEndian(code.AsSpan(p));
                    int lo = BinaryPrimitives.ReadInt32BigEndian(code.AsSpan(p + 4));
                    int hi = BinaryPrimitives.ReadInt32BigEndian(code.AsSpan(p + 8));
                    long cnt = (long)hi - lo + 1;
                    if (cnt < 0 || cnt > code.Length) { ins.Len = code.Length - pc; list.Add(ins); return list; }
                    ins.Operand = pc + def; ins.Operand2 = (int)cnt;
                    len = p + 12 + (int)cnt * 4 - pc;
                    break;
                }
                case LOOKUPSWITCH:
                {
                    int p = (pc + 4) & ~3;
                    if (p + 8 > code.Length) { ins.Len = code.Length - pc; list.Add(ins); return list; }
                    int def = BinaryPrimitives.ReadInt32BigEndian(code.AsSpan(p));
                    int n = BinaryPrimitives.ReadInt32BigEndian(code.AsSpan(p + 4));
                    if (n < 0 || n > code.Length) { ins.Len = code.Length - pc; list.Add(ins); return list; }
                    ins.Operand = pc + def; ins.Operand2 = n;
                    len = p + 8 + n * 8 - pc;
                    break;
                }
                case WIDE:
                {
                    if (pc + 1 >= code.Length) { ins.Len = 1; list.Add(ins); return list; }
                    byte w = code[pc + 1];
                    len = w == IINC ? 6 : 4;
                    ins.Operand = w;
                    break;
                }
                case BIPUSH: if (pc + 1 < code.Length) ins.Operand = (sbyte)code[pc + 1]; break;
                case SIPUSH: if (pc + 2 < code.Length) ins.Operand = BinaryPrimitives.ReadInt16BigEndian(code.AsSpan(pc + 1)); break;
                case LDC: if (pc + 1 < code.Length) ins.Operand = code[pc + 1]; break;
                case LDC_W: case LDC2_W: case GETSTATIC: case PUTSTATIC: case GETFIELD: case PUTFIELD:
                case INVOKEVIRTUAL: case INVOKESPECIAL: case INVOKESTATIC: case NEW: case ANEWARRAY: case CHECKCAST: case INSTANCEOF:
                case INVOKEINTERFACE: case INVOKEDYNAMIC: case MULTIANEWARRAY:
                    if (pc + 2 < code.Length) ins.Operand = BinaryPrimitives.ReadUInt16BigEndian(code.AsSpan(pc + 1)); break;
                case GOTO_W: case JSR_W:
                    if (pc + 4 < code.Length) ins.Operand = pc + BinaryPrimitives.ReadInt32BigEndian(code.AsSpan(pc + 1)); break;
                case NEWARRAY: case ILOAD: case 22: case 23: case 24: case ALOAD: case ISTORE: case 55: case 56: case 57: case ASTORE: case RET:
                    if (pc + 1 < code.Length) ins.Operand = code[pc + 1]; break;
                case IINC: if (pc + 2 < code.Length) { ins.Operand = code[pc + 1]; ins.Operand2 = (sbyte)code[pc + 2]; } break;
                default:
                    if (IsBranch(op) && pc + 2 < code.Length) ins.Operand = pc + BinaryPrimitives.ReadInt16BigEndian(code.AsSpan(pc + 1));
                    else if (op >= ICONST_M1 && op <= ICONST_5) ins.Operand = op - ICONST_0;
                    break;
            }
            if (len <= 0) len = 1;
            ins.Len = len;
            list.Add(ins);
            pc += len;
        }
        return list;
    }

    public static string Mnemonic(byte op) => op < Names.Length ? Names[op] : $"op{op}";

    private static readonly string[] Names = {
        "nop","aconst_null","iconst_m1","iconst_0","iconst_1","iconst_2","iconst_3","iconst_4","iconst_5","lconst_0","lconst_1",
        "fconst_0","fconst_1","fconst_2","dconst_0","dconst_1","bipush","sipush","ldc","ldc_w","ldc2_w","iload","lload","fload",
        "dload","aload","iload_0","iload_1","iload_2","iload_3","lload_0","lload_1","lload_2","lload_3","fload_0","fload_1",
        "fload_2","fload_3","dload_0","dload_1","dload_2","dload_3","aload_0","aload_1","aload_2","aload_3","iaload","laload",
        "faload","daload","aaload","baload","caload","saload","istore","lstore","fstore","dstore","astore","istore_0","istore_1",
        "istore_2","istore_3","lstore_0","lstore_1","lstore_2","lstore_3","fstore_0","fstore_1","fstore_2","fstore_3","dstore_0",
        "dstore_1","dstore_2","dstore_3","astore_0","astore_1","astore_2","astore_3","iastore","lastore","fastore","dastore",
        "aastore","bastore","castore","sastore","pop","pop2","dup","dup_x1","dup_x2","dup2","dup2_x1","dup2_x2","swap","iadd",
        "ladd","fadd","dadd","isub","lsub","fsub","dsub","imul","lmul","fmul","dmul","idiv","ldiv","fdiv","ddiv","irem","lrem",
        "frem","drem","ineg","lneg","fneg","dneg","ishl","lshl","ishr","lshr","iushr","lushr","iand","land","ior","lor","ixor",
        "lxor","iinc","i2l","i2f","i2d","l2i","l2f","l2d","f2i","f2l","f2d","d2i","d2l","d2f","i2b","i2c","i2s","lcmp","fcmpl",
        "fcmpg","dcmpl","dcmpg","ifeq","ifne","iflt","ifge","ifgt","ifle","if_icmpeq","if_icmpne","if_icmplt","if_icmpge",
        "if_icmpgt","if_icmple","if_acmpeq","if_acmpne","goto","jsr","ret","tableswitch","lookupswitch","ireturn","lreturn",
        "freturn","dreturn","areturn","return","getstatic","putstatic","getfield","putfield","invokevirtual","invokespecial",
        "invokestatic","invokeinterface","invokedynamic","new","newarray","anewarray","arraylength","athrow","checkcast",
        "instanceof","monitorenter","monitorexit","wide","multianewarray","ifnull","ifnonnull","goto_w","jsr_w","breakpoint",
    };
}

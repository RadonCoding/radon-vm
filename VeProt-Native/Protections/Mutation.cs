using Iced.Intel;
using System;
using System.Reflection;

namespace VeProt_Native.Protections {
    internal class Mutation : IProtection {
        private byte RotR8(byte value, int count) {
            return (byte)((value >> count) | (value << (8 - count)));
        }

        private short RotR16(short value, int count) {
            return (short)((value >> count) | (value << (16 - count)));
        }

        private int RotR32(int value, int count) {
            return (value >> count) | (value << (32 - count));
        }

        private long RotR64(long value, int count) {
            return (value >> count) | (value << (64 - count));
        }

        dynamic ToAsmRegister(Register reg) {
            switch (reg.GetSize()) {
                case 1:
                    return new AssemblerRegister8(reg);
                case 2:
                    return new AssemblerRegister16(reg);
                case 4:
                    return new AssemblerRegister32(reg);
                case 8:
                    return new AssemblerRegister64(reg);
            }
            throw new Exception();
        }

        public void Execute(Compiler compiler, uint oldSectionRVA, uint newSectionRVA, byte[] code) {
            var reader = new ByteArrayCodeReader(code.ToArray());
            var decoder = Decoder.Create(64, reader, oldSectionRVA);

            var instrs = new List<Instruction>();

            while (reader.CanReadByte) {
                decoder.Decode(out var instr);

                if (!instr.IsInvalid) {
                    instrs.Add(instr);
                }
            }

            var formatter = new NasmFormatter();
            var output = new StringOutput();

            foreach (var instr in instrs) {
                int offset = (int)(instr.IP - oldSectionRVA);

                switch (instr.OpCode.Code.Mnemonic()) {
                    case Mnemonic.Mov:
                        if (instr.Op0Kind == OpKind.Register && instr.Op1Kind.IsImmediate()) {
                            var offsets = decoder.GetConstantOffsets(instr);
                            var size = offsets.ImmediateSize;

                            if (size == 1 && !instr.Op0Register.IsGPR8()) break;
                            if (size == 2 && !instr.Op0Register.IsGPR16()) break;
                            if (size == 4 && !instr.Op0Register.IsGPR32()) break;
                            if (size == 8 && !instr.Op0Register.IsGPR64()) break;

                            //Random rand = new Random();

                            //dynamic add = 0;
                            //dynamic xor = 0;
                            //byte rot = (byte)rand.Next(1, 255);

                            //int index = offset + offsets.ImmediateOffset;

                            //switch (size) {
                            //    case 1: {
                            //            add = (byte)rand.Next(byte.MinValue, byte.MaxValue);
                            //            xor = (byte)rand.Next(byte.MinValue, byte.MaxValue);

                            //            byte value = code[index];
                            //            value = RotR8(value, rot);
                            //            value ^= (byte)xor;
                            //            value -= (byte)add;
                            //            value = (byte)~value;

                            //            code[index] = value;
                            //            break;
                            //        }
                            //    case 2: {
                            //            add = (short)rand.Next(short.MinValue, short.MaxValue);
                            //            xor = (short)rand.Next(short.MinValue, short.MaxValue);

                            //            short value = BitConverter.ToInt16(code, index);
                            //            value = RotR16(value, rot);
                            //            value ^= (short)xor;
                            //            value -= (short)add;
                            //            value = (short)~value;
                            //            BitConverter.GetBytes(value).CopyTo(code, index);
                            //            break;
                            //        }
                            //    case 4: {
                            //            add = rand.Next(int.MinValue, int.MaxValue);
                            //            xor = rand.Next(int.MinValue, int.MaxValue);

                            //            int value = BitConverter.ToInt32(code, index);
                            //            value = RotR32(value, rot);
                            //            value ^= xor;
                            //            value -= add;
                            //            value = ~value;
                            //            BitConverter.GetBytes(value).CopyTo(code, index);
                            //            break;
                            //        }
                            //    case 8: {
                            //            add = rand.Next(int.MinValue, int.MaxValue);
                            //            xor = rand.Next(int.MinValue, int.MaxValue);

                            //            long value = BitConverter.ToInt64(code, index);
                            //            value = RotR64(value, rot);
                            //            value ^= xor;
                            //            value -= add;
                            //            value = ~value;
                            //            BitConverter.GetBytes(value).CopyTo(code, index);
                            //            break;
                            //        }
                            //}

                            //dynamic reg = ToAsmRegister(instr.Op0Register);

                            Assembler asm = new Assembler(64);
                            //asm.pushf();
                            //asm.not(reg);
                            //asm.add(reg, add);
                            //asm.xor(reg, xor);
                            //asm.rol(reg, rot);
                            //asm.popf();
                            asm.nop();

#if DEBUG
                            Console.Write("[*] Mutating: ");

                            formatter.Format(instr, output);
                            Console.Write("0x{0}", (compiler.Image.ImageBase + instr.IP).ToString("X16"));
                            Console.Write(", ");

                            Console.Write("new byte[] {");
                            Console.Write(" ");

                            for (int i = 0; i < instr.Length; i++) {
                                Console.Write("0x{0}", code[offset + i].ToString("X2"));
                                Console.Write(" ");
                            }
                            Console.Write("}");

                            Console.Write(", ");
                            Console.WriteLine(output.ToStringAndReset());
#endif

                            using (var ms = new MemoryStream()) {
                                asm.Assemble(new StreamCodeWriter(ms), instr.NextIP);
                                byte[] assembled = ms.ToArray();
                                compiler.Insert(offset + instr.Length, assembled);
                            }
                        }
                        break;
                }
            }
        }
    }
}

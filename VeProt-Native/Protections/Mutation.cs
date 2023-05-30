using Iced.Intel;
using System;
using System.Diagnostics;
using System.Numerics;
using System.Reflection;

namespace VeProt_Native.Protections {
    internal class Mutation : IProtection {
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

        private byte Rotr8(byte value, int shift) {
            return (byte)((value >> shift) | (value << (8 - shift)));
        }

        private ushort Rotr16(ushort value, int shift) {
            return (ushort)((value >> shift) | (value << (16 - shift)));
        }

        private uint Rotr32(uint value, int shift) {
            return (value >> shift) | (value << (32 - shift));
        }

        private ulong Rotr64(ulong value, int shift) {
            return (value >> shift) | (value << (64 - shift));
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

            foreach (var instr in instrs) {
                int offset = (int)(instr.IP - oldSectionRVA);

                switch (instr.OpCode.Code.Mnemonic()) {
                    case Mnemonic.Mov:
                        if (instr.Op0Kind == OpKind.Register && instr.Op1Kind.IsImmediate()) {
                            var offsets = decoder.GetConstantOffsets(instr);
                            var size = offsets.ImmediateSize;

                            //if (!instr.Op0Register.IsGPR()) break;

                            Random rand = new Random();

                            byte add = (byte)rand.Next(1, byte.MaxValue);
                            byte xor = (byte)rand.Next(1, byte.MaxValue);
                            byte rot = (byte)rand.Next(1, byte.MaxValue);

                            int index = offset + offsets.ImmediateOffset;

                            switch (size) {
                                case 1: {
                                        /* 
                                         * We need to mask out the required bits of count 
                                         * manually, as the shift operaters will promote a byte to uint, 
                                         * and will not mask out the correct number of count bits.
                                        */
                                        code[index] = (byte)~((Rotr8(code[index], rot & 0x7) ^ xor) - add);
                                        break;
                                    }
                                default:
                                    continue;
                                case 2: {
                                        ushort value = BitConverter.ToUInt16(code, index);
                                        value = (ushort)~((Rotr16(value, rot) ^ xor) - add);
                                        BitConverter.GetBytes(value).CopyTo(code, index);
                                        break;
                                    }
                                case 4: {
                                        uint value = BitConverter.ToUInt32(code, index);
                                        value = ~((Rotr32(value, rot) ^ xor) - add);
                                        BitConverter.GetBytes(value).CopyTo(code, index);
                                        break;
                                    }
                                case 8: {
                                        ulong value = BitConverter.ToUInt64(code, index);
                                        value = ~((Rotr64(value, rot) ^ xor) - add);
                                        BitConverter.GetBytes(value).CopyTo(code, index);
                                        break;
                                    }
                            }

                            dynamic reg = ToAsmRegister(instr.Op0Register);

                            Assembler asm = new Assembler(64);
                            asm.pushf();
                            asm.not(reg);
                            asm.add(reg, add);
                            asm.xor(reg, xor);
                            asm.rol(reg, rot);
                            asm.popf();

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

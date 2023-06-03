using Iced.Intel;
using System.Diagnostics;

namespace VeProt_Native.Protections {
    internal class Mutation : IProtection {
        private static Random _rand = new Random();

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

        private void MutateMov(Compiler compiler, Decoder decoder, Instruction instr, byte[] code, int offset) {
            if (instr.Op0Kind != OpKind.Register || !instr.Op1Kind.IsImmediate()) return;

            var offsets = decoder.GetConstantOffsets(instr);
            var size = offsets.ImmediateSize;

            byte add = (byte)_rand.Next(1, byte.MaxValue);
            byte xor = (byte)_rand.Next(1, byte.MaxValue);
            byte rot = (byte)_rand.Next(1, byte.MaxValue);

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

            Assembler ass = new Assembler(64);
            ass.pushf();
            ass.not(reg);
            ass.add(reg, add);
            ass.xor(reg, xor);
            ass.rol(reg, rot);
            ass.popf();

            using (var ms = new MemoryStream()) {
                ass.Assemble(new StreamCodeWriter(ms), instr.NextIP);
                byte[] assembled = ms.ToArray();
                compiler.Insert(offset + instr.Length, assembled);
            }
        }

        private void MutateAdd(Compiler compiler, Decoder decoder, Instruction instr, byte[] code, int offset) {
            if (instr.Op0Register.GetSize() != 8) return;
            if (instr.Op0Kind != OpKind.Register || instr.Op1Kind != OpKind.Register) return;

            if (instr.Op0Register == instr.Op1Register) return;
            if (instr.Op0Register == Register.RSP || instr.Op1Register == Register.RSP) return;
            if (instr.Op0Register.GetSize() != instr.Op1Register.GetSize()) return;

            dynamic first = ToAsmRegister(instr.Op0Register);
            dynamic second = ToAsmRegister(instr.Op1Register);
            
            Assembler ass = new Assembler(64);
            ass.push(second);
            ass.not(second);
            ass.sub(first, second);
            ass.pop(second);
            ass.sub(first, 1);

            using (var ms = new MemoryStream()) {
                ass.Assemble(new StreamCodeWriter(ms), instr.IP);
                byte[] assembled = ms.ToArray();
                compiler.Replace(offset, instr.Length, assembled);
            }
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
                        MutateMov(compiler, decoder, instr, code, offset);
                        break;
                    case Mnemonic.Add:
                        MutateAdd(compiler, decoder, instr, code, offset);
                        break;
                }
            }
        }
    }
}

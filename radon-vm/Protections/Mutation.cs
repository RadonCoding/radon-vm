using Iced.Intel;
using System.Reflection.Emit;
using System;
using System.Numerics;

namespace radon_vm.Protections
{
    internal class Mutation : IProtection
    {
        private static Random _rand = new Random();

        dynamic ToAsmRegister(Register reg)
        {
            switch (reg.GetSize())
            {
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

        private byte Rotr8(byte value, int shift)
        {
            return (byte)((value >> shift) | (value << (8 - shift)));
        }

        private ushort Rotr16(ushort value, int shift)
        {
            return (ushort)((value >> shift) | (value << (16 - shift)));
        }

        private uint Rotr32(uint value, int shift)
        {
            return (value >> shift) | (value << (32 - shift));
        }

        private ulong Rotr64(ulong value, int shift)
        {
            return (value >> shift) | (value << (64 - shift));
        }

        private void MutateMovRegImm(Compiler compiler, Decoder decoder, Instruction instr, byte[] code, int offset)
        {
            Console.WriteLine("Mutating: {0}", instr);

            var offsets = decoder.GetConstantOffsets(instr);
            var size = offsets.ImmediateSize;

            int index = offset + offsets.ImmediateOffset;

            dynamic reg = ToAsmRegister(instr.Op0Register);

            Assembler ass = new Assembler(64);

            switch (size)
            {
                case 1:
                    {
                        byte add = (byte)(_rand.Next() % 255 + 1);
                        byte xor = (byte)(_rand.Next() % 255 + 1);
                        code[index] = (byte)~((code[index] ^ xor) - add);

                        ass.pushf();
                        ass.not(reg);
                        ass.add(reg, (sbyte)add);
                        ass.xor(reg, (sbyte)xor);
                        ass.popf();
                        break;
                    }
                case 2:
                    {
                        short add = (short)_rand.Next(short.MaxValue / 2, short.MaxValue);
                        short xor = (short)_rand.Next(short.MaxValue / 2, short.MaxValue);
                        short value = BitConverter.ToInt16(code, index);
                        value = (short)~((value ^ xor) - add);
                        BitConverter.GetBytes(value).CopyTo(code, index);

                        ass.pushf();
                        ass.not(reg);
                        ass.add(reg, add);
                        ass.xor(reg, xor);
                        ass.popf();
                        break;
                    }
                case 4:
                    {
                        int add = _rand.Next(short.MaxValue / 2, short.MaxValue);
                        int xor = _rand.Next(short.MaxValue / 2, short.MaxValue);
                        int value = BitConverter.ToInt32(code, index);
                        value = ~((value ^ xor) - add);
                        BitConverter.GetBytes(value).CopyTo(code, index);

                        ass.pushf();
                        ass.not(reg);
                        ass.add(reg, add);
                        ass.xor(reg, xor);
                        ass.popf();
                        break;
                    }
                case 8:
                    {
                        int add = _rand.Next(int.MaxValue / 2, int.MaxValue);
                        int xor = _rand.Next(int.MaxValue / 2, int.MaxValue);
                        long value = BitConverter.ToInt64(code, index);
                        value = ~((value ^ xor) - add);
                        BitConverter.GetBytes(value).CopyTo(code, index);

                        ass.pushf();
                        ass.not(reg);
                        ass.add(reg, add);
                        ass.xor(reg, xor);
                        ass.popf();
                        break;
                    }
                default:
                    throw new NotImplementedException();
            }

            using (var ms = new MemoryStream())
            {
                ass.Assemble(new StreamCodeWriter(ms), instr.NextIP);
                byte[] assembled = ms.ToArray();
                compiler.Insert(offset + instr.Length, assembled);
            }
        }

        private void MutateMovRegReg(Compiler compiler, Decoder decoder, Instruction instr, byte[] code, int offset)
        {
            Console.WriteLine("Mutating: {0}", instr);

            dynamic reg0 = ToAsmRegister(instr.Op0Register);
            dynamic reg1 = ToAsmRegister(instr.Op1Register);

            Assembler ass = new Assembler(64);
            ass.push(reg1);
            ass.pop(reg0);

            using (var ms = new MemoryStream())
            {
                ass.Assemble(new StreamCodeWriter(ms), instr.IP);
                byte[] assembled = ms.ToArray();
                compiler.Replace(offset, instr.Length, assembled);
            }
        }

        public void Execute(Compiler compiler, uint oldSectionRVA, uint newSectionRVA, byte[] code)
        {
            var reader = new ByteArrayCodeReader(code.ToArray());
            var decoder = Decoder.Create(64, reader, oldSectionRVA);

            var instrs = new List<Instruction>();

            while (reader.CanReadByte)
            {
                decoder.Decode(out var instr);

                if (!instr.IsInvalid)
                {
                    instrs.Add(instr);
                }
            }

            foreach (var instr in instrs)
            {
                int offset = (int)(instr.IP - oldSectionRVA);

                switch (instr.OpCode.Code.Mnemonic())
                {
                    case Mnemonic.Mov:
                        if (instr.Op0Kind == OpKind.Register && instr.Op1Kind.IsImmediate())
                        {
                            MutateMovRegImm(compiler, decoder, instr, code, offset);
                        }
                        else if (instr.Op0Register.GetSize() == 8 && instr.Op1Register.GetSize() == 8)
                        {
                            MutateMovRegReg(compiler, decoder, instr, code, offset);
                        }
                        break;
                }
            }
        }
    }
}

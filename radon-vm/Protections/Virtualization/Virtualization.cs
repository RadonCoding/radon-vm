using Iced.Intel;
using System;
using static Iced.Intel.AssemblerRegisters;

namespace VeProt_Native.Protections.Virtualization
{
    internal class Virtualization : IProtection
    {
        private static Mnemonic[] SUPPORTED_MNEMONICS = {
            Mnemonic.Add
        };

        enum VMRegister
        {
            RAX,
            RCX,
            RDX,
            RBX,
            RSP,
            RBP,
            RSI,
            RDI,
            R8,
            R9,
            R10,
            R11,
            R12,
            R13,
            R14,
            R15,
        }

        enum VMRegisterPart
        {
            Higher,
            Lower,
            None
        }

        private VMRegister ToVMRegister(Register reg)
        {
            switch (reg)
            {
                case Register.RAX:
                    return VMRegister.RAX;
                case Register.EAX:
                    return VMRegister.RAX;
                case Register.AX:
                    return VMRegister.RAX;
                case Register.AH:
                    return VMRegister.RAX;
                case Register.AL:
                    return VMRegister.RAX;

                case Register.RCX:
                    return VMRegister.RCX;
                case Register.ECX:
                    return VMRegister.RCX;
                case Register.CX:
                    return VMRegister.RCX;
                case Register.CH:
                    return VMRegister.RCX;
                case Register.CL:
                    return VMRegister.RCX;

                case Register.RDX:
                    return VMRegister.RDX;
                case Register.EDX:
                    return VMRegister.RDX;
                case Register.DX:
                    return VMRegister.RDX;
                case Register.DH:
                    return VMRegister.RDX;
                case Register.DL:
                    return VMRegister.RDX;

                case Register.RBX:
                    return VMRegister.RBX;
                case Register.EBX:
                    return VMRegister.RBX;
                case Register.BX:
                    return VMRegister.RBX;
                case Register.BH:
                    return VMRegister.RBX;
                case Register.BL:
                    return VMRegister.RBX;

                case Register.RSP:
                    return VMRegister.RSP;
                case Register.ESP:
                    return VMRegister.RSP;
                case Register.SP:
                    return VMRegister.RSP;

                case Register.RBP:
                    return VMRegister.RBP;
                case Register.EBP:
                    return VMRegister.RBP;
                case Register.BP:
                    return VMRegister.RBP;

                case Register.RSI:
                    return VMRegister.RSI;
                case Register.ESI:
                    return VMRegister.RSI;
                case Register.SI:
                    return VMRegister.RSI;

                case Register.RDI:
                    return VMRegister.RDI;
                case Register.EDI:
                    return VMRegister.RDI;
                case Register.DI:
                    return VMRegister.RDI;

                case Register.R8:
                    return VMRegister.R8;
                case Register.R8D:
                    return VMRegister.R8;
                case Register.R8W:
                    return VMRegister.R8;

                case Register.R9:
                    return VMRegister.R9;
                case Register.R9D:
                    return VMRegister.R9;
                case Register.R9W:
                    return VMRegister.R9;

                case Register.R10:
                    return VMRegister.R10;
                case Register.R10D:
                    return VMRegister.R10;
                case Register.R10W:
                    return VMRegister.R10;

                case Register.R11:
                    return VMRegister.R11;
                case Register.R11D:
                    return VMRegister.R11;
                case Register.R11W:
                    return VMRegister.R11;

                case Register.R12:
                    return VMRegister.R12;
                case Register.R12D:
                    return VMRegister.R12;
                case Register.R12W:
                    return VMRegister.R12;

                case Register.R13:
                    return VMRegister.R13;
                case Register.R13D:
                    return VMRegister.R13;
                case Register.R13W:
                    return VMRegister.R13;

                case Register.R14:
                    return VMRegister.R14;
                case Register.R14D:
                    return VMRegister.R14;
                case Register.R14W:
                    return VMRegister.R14;

                case Register.R15:
                    return VMRegister.R15;
                case Register.R15D:
                    return VMRegister.R15;
                case Register.R15W:
                    return VMRegister.R15;

                default:
                    throw new NotImplementedException();
            }
        }

        private VMRegisterPart GetRegisterPart(Register reg)
        {
            switch (reg)
            {
                case Register.AH:
                    return VMRegisterPart.Higher;
                case Register.AL:
                    return VMRegisterPart.Lower;

                case Register.CH:
                    return VMRegisterPart.Higher;
                case Register.CL:
                    return VMRegisterPart.Lower;

                case Register.DH:
                    return VMRegisterPart.Higher;
                case Register.DL:
                    return VMRegisterPart.Lower;

                case Register.BH:
                    return VMRegisterPart.Higher;
                case Register.BL:
                    return VMRegisterPart.Lower;

                default:
                    return VMRegisterPart.None;
            }
        }

        private byte[] Convert(Instruction instr)
        {
            List<byte> bytes = new List<byte>
            {
                (byte)instr.Mnemonic,
                (byte)instr.OpCount
            };

            for (int i = 0; i < instr.OpCount; i++)
            {
                OpKind kind = instr.GetOpKind(i);
                bytes.Add((byte)kind);

                if (kind == OpKind.Register)
                {
                    Register reg = instr.GetOpRegister(i);
                    int size = reg.GetSize();
                    bytes.Add((byte)size);
                    bytes.Add((byte)ToVMRegister(reg));
                    bytes.Add((byte)GetRegisterPart(reg));
                }
                else if (kind.IsImmediate())
                {
                    byte[] imm = BitConverter.GetBytes(instr.GetImmediate(i));
                    bytes.Add((byte)imm.Length);
                    bytes.AddRange(imm);
                }
                else if (kind == OpKind.Memory)
                {
                    Register reg = instr.MemoryBase;
                    bytes.Add((byte)reg.GetSize());
                    bytes.Add((byte)ToVMRegister(reg));
                    bytes.Add((byte)GetRegisterPart(reg));
                }
                else
                {
                    throw new NotImplementedException();
                }
            }
            return bytes.ToArray();
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

            var converted = new Dictionary<int, byte[]>();

            foreach (var instr in instrs)
            {
                if (instr.Op0Register == Register.RSP || instr.Op0Register == Register.RBP) continue;

                int offset = (int)(instr.IP - oldSectionRVA);

                if (SUPPORTED_MNEMONICS.Contains(instr.Mnemonic))
                {
                    // Convert the instruction to byte code format [opcode] [operands]
                    byte[] bytes = Convert(instr);
                    converted.Add(offset, bytes);
                }
            }

            uint bytecode = compiler.Injector.Insert("VMBytecode", converted
                .SelectMany(x => x.Value)
                .ToArray());

            uint entry = compiler.Injector.Inject("VMEntry");
            uint dispatcher = compiler.Injector.Inject("VMDispatcher");
            uint exit = compiler.Injector.Inject("VMExit");

            foreach (var instr in instrs)
            {
                if (instr.Op0Register == Register.RSP || instr.Op0Register == Register.RBP) continue;

                int offset = (int)(instr.IP - oldSectionRVA);

                if (SUPPORTED_MNEMONICS.Contains(instr.Mnemonic))
                {
                    Console.WriteLine("Virtualizing: {0}", instr);

                    Assembler ass = new Assembler(64);

                    int index = converted
                        .Where(x => x.Key < offset)
                        .Sum(x => x.Value.Length);

                    // VMEntry returns the address to the beginning of VMState
                    ass.call(entry);

                    ass.mov(rcx, rax);
                    ass.AddInstruction(Instruction.Create(Code.Lea_r64_m, rdx,
                        new MemoryOperand(Register.RIP, Register.None, 1, bytecode, 1)));
                    ass.mov(r8d, index);
                    ass.call(dispatcher);

                    ass.mov(rcx, rax);
                    ass.call(exit);

                    using (var ms = new MemoryStream())
                    {
                        ass.Assemble(new StreamCodeWriter(ms), instr.IP);
                        byte[] assembled = ms.ToArray();
                        compiler.Replace(offset, instr.Length, assembled);
                    }
                }
            }
        }
    }
}

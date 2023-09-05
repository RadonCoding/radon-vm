using Iced.Intel;
using System;
using System.Diagnostics;
using static Iced.Intel.AssemblerRegisters;

namespace radon_vm.Protections
{
    internal class Virtualization : IProtection
    {
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
                case Register.SPL:
                    return VMRegister.RSP;

                case Register.RBP:
                    return VMRegister.RBP;
                case Register.EBP:
                    return VMRegister.RBP;
                case Register.BP:
                    return VMRegister.RBP;
                case Register.BPL:
                    return VMRegister.RBP;

                case Register.RSI:
                    return VMRegister.RSI;
                case Register.ESI:
                    return VMRegister.RSI;
                case Register.SI:
                    return VMRegister.RSI;
                case Register.SIL:
                    return VMRegister.RSI;

                case Register.RDI:
                    return VMRegister.RDI;
                case Register.EDI:
                    return VMRegister.RDI;
                case Register.DI:
                    return VMRegister.RDI;
                case Register.DIL:
                    return VMRegister.RDI;

                case Register.R8:
                    return VMRegister.R8;
                case Register.R8D:
                    return VMRegister.R8;
                case Register.R8W:
                    return VMRegister.R8;
                case Register.R8L:
                    return VMRegister.R8;

                case Register.R9:
                    return VMRegister.R9;
                case Register.R9D:
                    return VMRegister.R9;
                case Register.R9W:
                    return VMRegister.R9;
                case Register.R9L:
                    return VMRegister.R9;

                case Register.R10:
                    return VMRegister.R10;
                case Register.R10D:
                    return VMRegister.R10;
                case Register.R10W:
                    return VMRegister.R10;
                case Register.R10L:
                    return VMRegister.R10;

                case Register.R11:
                    return VMRegister.R11;
                case Register.R11D:
                    return VMRegister.R11;
                case Register.R11W:
                    return VMRegister.R11;
                case Register.R11L:
                    return VMRegister.R11;

                case Register.R12:
                    return VMRegister.R12;
                case Register.R12D:
                    return VMRegister.R12;
                case Register.R12W:
                    return VMRegister.R12;
                case Register.R12L:
                    return VMRegister.R12;

                case Register.R13:
                    return VMRegister.R13;
                case Register.R13D:
                    return VMRegister.R13;
                case Register.R13W:
                    return VMRegister.R13;
                case Register.R13L:
                    return VMRegister.R13;

                case Register.R14:
                    return VMRegister.R14;
                case Register.R14D:
                    return VMRegister.R14;
                case Register.R14W:
                    return VMRegister.R14;
                case Register.R14L:
                    return VMRegister.R14;

                case Register.R15:
                    return VMRegister.R15;
                case Register.R15D:
                    return VMRegister.R15;
                case Register.R15W:
                    return VMRegister.R15;
                case Register.R15L:
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

        private byte[] Convert(int index, Instruction instr)
        {
            var bytes = new List<byte>();
            bytes.AddRange(BitConverter.GetBytes((short)instr.Mnemonic));
            bytes.Add((byte)instr.OpCount);

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

        public static byte[] Crypt(byte[] bytes, int key)
        {
            byte[] encrypted = new byte[bytes.Length];

            for (int i = 0; i < bytes.Length; i++)
            {
                encrypted[i] = (byte)(bytes[i] ^ key);
            }
            return encrypted;
        }

        private void Virtualize(Compiler compiler, Instruction instr, uint oldSectionRVA, uint newSectionRVA, int offset, int index, uint bytecode, uint entry, uint dispatcher, uint exit)
        {
            Console.WriteLine("Virtualizing: {0}", instr);

            Assembler ass = new Assembler(64);

            // VMEntry returns the address to the beginning of VMState
            ass.call(entry);

            ass.mov(rcx, rax);

            ass.push(rcx);

            ass.AddInstruction(Instruction.Create(Code.Lea_r64_m, rdx,
                new MemoryOperand(Register.RIP, Register.None, 1, bytecode, 1)));
            ass.mov(r8d, index);
            ass.call(dispatcher);

            ass.pop(rcx);

            ass.call(exit);

            using (var ms = new MemoryStream())
            {
                ass.Assemble(new StreamCodeWriter(ms), instr.IP - (newSectionRVA - oldSectionRVA));
                byte[] assembled = ms.ToArray();
                compiler.Replace(offset, instr.Length, assembled);
            }
        }

        private bool IsSupported(Instruction instr)
        {
            if (instr.MemoryBase != Register.RIP && instr.MemoryBase != Register.RBP && instr.MemoryBase != Register.RSP && 
                instr.Op1Kind != OpKind.Memory && instr.Op0Register != Register.RSP && instr.Op0Register != Register.RBP && 
                (instr.Mnemonic == Mnemonic.Add || instr.Mnemonic == Mnemonic.Sub))
            {
                return true;
            } 
            return false;
        }

        public void Execute(Compiler compiler, uint oldSectionRVA, uint newSectionRVA, byte[] code)
        {
            var instrs = compiler.GetInstructions(code, newSectionRVA);

            var converted = new Dictionary<int, byte[]>();

            foreach (var instr in instrs)
            {
                int offset = (int)(instr.IP - newSectionRVA);

                if (IsSupported(instr))
                {
                    // Convert the instruction to byte code format [opcode] [operands]
                    int index = converted
                        .Where(x => x.Key < offset)
                        .Sum(x => x.Value.Length);
                    var bytes = Crypt(Convert(index, instr), index).ToList();
                    bytes.Insert(0, (byte)bytes.Count);
                    converted.Add(offset, bytes.ToArray());
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
                int offset = (int)(instr.IP - newSectionRVA);

                if (IsSupported(instr))
                {
                    int index = converted
                            .Where(x => x.Key < offset)
                            .Sum(x => x.Value.Length);
                    Virtualize(compiler, instr, oldSectionRVA, newSectionRVA, offset, index, bytecode, entry, dispatcher, exit);
                }
            }
        }
    }
}

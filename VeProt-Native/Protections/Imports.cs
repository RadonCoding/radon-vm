﻿using Iced.Intel;
using System.Runtime.InteropServices;
using static Iced.Intel.AssemblerRegisters;

namespace VeProt_Native.Protections {
    internal class Imports : IProtection {
        public unsafe void Execute(Compiler compiler, uint oldSectionRVA, uint newSectionRVA, byte[] code) {
            var reader = new ByteArrayCodeReader(code.ToArray());
            var decoder = Decoder.Create(64, reader, oldSectionRVA);

            var instrs = new List<Instruction>();

            while (reader.CanReadByte) {
                decoder.Decode(out var instr);

                if (!instr.IsInvalid) {
                    instrs.Add(instr);
                }
            }

            uint resolve = compiler.Injector.Inject("Resolve");

            foreach (var instr in instrs) {
                int offset = (int)(instr.IP - oldSectionRVA);

                if (instr.Mnemonic == Mnemonic.Call) {
                    ulong target = 0;

                    switch (instr.Op0Kind) {
                        case OpKind.NearBranch16:
                        case OpKind.NearBranch32:
                        case OpKind.NearBranch64:
                            target = instr.NearBranchTarget;
                            break;
                        case OpKind.Memory:
                            target = instr.IPRelativeMemoryAddress;
                            break;
                        default:
                            continue;
                    }
                    
                    // Normalize the target address
                    target += newSectionRVA - oldSectionRVA;

                    foreach (var import in compiler.Image.Imports) {
                        foreach (var symbol in import.Symbols) {
                            if (symbol.AddressTableEntry?.Rva == target) {
                                uint func = Runtime.Hash(Marshal.StringToHGlobalAnsi(symbol.Name));
                                uint lib = Runtime.Hash(Marshal.StringToHGlobalAnsi(import.Name));

                                Assembler ass = new Assembler(64);
                                //ass.mov(ecx, lib);
                                //ass.mov(edx, func);
                                //ass.call(resolve);
                                //ass.call(rax);
                                ass.nop();

                                using (var ms = new MemoryStream()) {
                                    //ass.Assemble(new StreamCodeWriter(ms), instr.IP);
                                    ass.Assemble(new StreamCodeWriter(ms), instr.NextIP);
                                    byte[] assembled = ms.ToArray();
                                    //compiler.Replace(offset, instr.Length, assembled);
                                    compiler.Insert(offset + instr.Length, assembled);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}
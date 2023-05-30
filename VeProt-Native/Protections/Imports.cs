using Iced.Intel;
using System.Runtime.InteropServices;

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

                    foreach (var import in compiler.Image.Imports) {
                        foreach (var symbol in import.Symbols) {
                            if (symbol.AddressTableEntry?.Rva == target) {
                                int func = Runtime.Hash(Marshal.StringToHGlobalAnsi(symbol.Name));
                                int lib = Runtime.Hash(Marshal.StringToHGlobalAnsi(import.Name));

                                Assembler asm = new Assembler(64);
                                asm.push(lib);
                                asm.push(func);
                                asm.call(resolve);

                                using (var ms = new MemoryStream()) {
                                    asm.Assemble(new StreamCodeWriter(ms), instr.IP);
                                    byte[] assembled = ms.ToArray();
                                    compiler.Replace(offset, instr.Length, assembled);
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

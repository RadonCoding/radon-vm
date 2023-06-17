using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace VeProt_Native.Protections.Virtualization {
    internal class Virtualization : IProtection {
        private static Mnemonic[] SUPPORTED_MNEMONICS = {
            Mnemonic.Add
        };

        private byte[] Convert(Instruction instr) {
            throw new NotImplementedException();
        }

        private VMOpCode ToVMOpCode(Mnemonic mnemonic) {
            return mnemonic switch {
                Mnemonic.Add => VMOpCode.Add,
                _ => throw new NotImplementedException()
            };
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

            var bytecode = new Dictionary<int, byte[]>();

            foreach (var instr in instrs) {
                int offset = (int)(instr.IP - oldSectionRVA);

                if (SUPPORTED_MNEMONICS.Contains(instr.Mnemonic)) {
                    // Convert the instruction to byte code format [opcode] [operands]
                    byte[] converted = Convert(instr);
                    bytecode.Add(offset, converted);
                }
            }

            uint vmBytecode = compiler.Injector.Insert("VMBytecode", bytecode
                .SelectMany(x => x.Value)
                .ToArray());

            uint vmEntry = compiler.Injector.Inject("VMEntry");
            uint vmDispatcher = compiler.Injector.Inject("VMDispatcher");
            uint vmExit = compiler.Injector.Inject("VMExit");

            foreach (var instr in instrs) {
                int offset = (int)(instr.IP - oldSectionRVA);

                if (SUPPORTED_MNEMONICS.Contains(instr.Mnemonic)) {
                    Assembler ass = new Assembler(64);

                    byte[] converted = bytecode[offset];
                    int index = bytecode
                        .Where(x => x.Key < offset)
                        .Sum(x => x.Value.Length);
                    int length = converted.Length;

                    ass.call(vmEntry);      // Call the VM entry
                    ass.mov(rcx, index);    // Pass the index of the bytecode
                    ass.mov(rdx, length);   // Pass the length of the bytecode
                    ass.call(vmDispatcher); // Call the VM dispatcher
                    ass.call(vmExit);       // Call the VM exit

                    using (var ms = new MemoryStream()) {
                        ass.Assemble(new StreamCodeWriter(ms), instr.IP);
                        byte[] assembled = ms.ToArray();
                        compiler.Replace(offset, instr.Length, assembled);
                    }
                }
            }
        }
    }
}

using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace radon_vm.Protections
{
    internal class ControlFlow : IProtection
    {
        private static Random _rand = new Random();

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

            var block = new Dictionary<int, Instruction>();

            foreach (var instr in instrs)
            {
                if (instr.FlowControl == FlowControl.Next)
                {
                    block.Add(block.Count, instr);
                }
                else
                {
                    if (block.Count > 1)
                    {
                        int start = (int)(block[0].IP - oldSectionRVA);
                        int end = (int)(block[block.Count - 1].NextIP - oldSectionRVA);

                        Assembler ass = new Assembler(64);

                        // Randomize the order of the block
                        block.OrderBy(x => _rand.Next()).ToDictionary(x => x.Key, x => x.Value);

                        // Preserve rcx
                        ass.push(rcx);

                        // Initialize rcx to 0
                        ass.xor(rcx, rcx);

                        // Jump to dispatcher
                        ass.jmp(ass.F);

                        var labels = new Dictionary<int, Label>();

                        foreach (var kv in block)
                        {
                            var label = ass.CreateLabel();
                            ass.AddInstruction(kv.Value);
                            ass.inc(rcx);
                            ass.jmp(ass.F);
                            labels.Add(kv.Key, label);
                        }

                        // Dispatcher
                        ass.AnonymousLabel();

                        ass.cmp(rcx, block.Count);
                        ass.jmp(ass.F);

                        foreach (var kv in block)
                        {
                            ass.cmp(rcx, kv.Key);
                            ass.je(labels[kv.Key]);
                        }

                        ass.AnonymousLabel();

                        // Restore rcx
                        ass.pop(rcx);

                        using (var ms = new MemoryStream())
                        {
                            ass.Assemble(new StreamCodeWriter(ms), block[0].IP);
                            byte[] assembled = ms.ToArray();

                            Console.WriteLine("[BLOCK START]");

                            var members = compiler.GetInstructions(assembled, block[0].IP);

                            for (int i = 0; i < members.Count; i++)
                            {
                                Console.WriteLine("{0}      {1}", members[i].IP.ToString("X16"), members[i]);
                            }
                            Console.WriteLine("[BLOCK END]");

                            compiler.Replace(start, end - start, assembled);
                        }
                    }
                    block.Clear();
                }
            }
        }
    }
}

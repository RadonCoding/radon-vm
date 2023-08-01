using AsmResolver.PE.File.Headers;
using Iced.Intel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static Iced.Intel.AssemblerRegisters;

namespace VeProt_Native
{
    internal class InjectHelper
    {
        public static int SECTION_SIZE = 0x2000;

        public Dictionary<string, uint> Injected { get { return _injected; } }
        public byte[] Bytes { get { return _bytes; } }

        public uint Rva { get { return _rva; } }

        private Dictionary<string, uint> _injected;
        private byte[] _bytes;

        private uint _rva;
        private int _offset;
        private Compiler _compiler;

        public InjectHelper(Compiler compiler, uint rva)
        {
            _injected = new Dictionary<string, uint>();
            _bytes = new byte[SECTION_SIZE];
            _compiler = compiler;
            _rva = rva;
        }

        public uint Insert(string name, byte[] data)
        {
            Array.Copy(data, 0, _bytes, _offset, data.Length);
            _injected.Add(name, (uint)(_rva + _offset));
            _offset += data.Length;
            return _injected[name];
        }

        public uint Insert(string name, Assembler ass)
        {
            using (var ms = new MemoryStream())
            {
                ass.Assemble(new StreamCodeWriter(ms), (uint)(_rva + _offset));
                byte[] assembled = ms.ToArray();
                Array.Copy(assembled, 0, _bytes, _offset, assembled.Length);
                _injected.Add(name, (uint)(_rva + _offset));
                _offset += assembled.Length;
                return _injected[name];
            }
        }

        private void SetTarget(Instruction instr, ulong target)
        {
            if (instr.IsIPRelativeMemoryOperand)
            {
                if (instr.MemoryDisplSize == 8)
                {
                    instr.MemoryDisplacement64 = target;
                }
                else
                {
                    instr.MemoryDisplacement32 = (uint)target;
                }
            }
            else
            {
                switch (instr.Op0Kind)
                {
                    case OpKind.NearBranch16:
                        instr.NearBranch16 = (ushort)target;
                        break;
                    case OpKind.NearBranch32:
                        instr.NearBranch32 = (uint)target;
                        break;
                    case OpKind.NearBranch64:
                        instr.NearBranch64 = target;
                        break;
                }
            }
        }

        public unsafe uint Inject(string name)
        {
            if (_injected.ContainsKey(name))
            {
                return _injected[name];
            }

            IntPtr func = Runtime.GetFunction(name);
            uint len = Runtime.GetSize(name);

            byte[] body = new byte[len];
            Marshal.Copy(func, body, 0, body.Length);

            var symbol = Runtime.GetSymbol(name);
            ulong ip = symbol.Address - symbol.ModBase;

            // Decompile
            var instrs = _compiler.GetInstructions(body, ip);

            ulong start = symbol.Address - symbol.ModBase;
            ulong end = start + symbol.Size;

            // Fix calls
            for (int i = 0; i < instrs.Count; i++)
            {
                var instr = instrs[i];

                if (instr.IsIPRelative())
                {
                    ulong target = instr.IsIPRelativeMemoryOperand ? instr.IPRelativeMemoryAddress : instr.NearBranchTarget;

                    if (!(target >= start && target < end))
                    {
                        string current = Runtime.GetName(target);

                        bool found = false;

                        foreach (var lib in _compiler.Image.Imports)
                        {
                            foreach (var import in lib.Symbols)
                            {
                                if (import.Name == current)
                                {
                                    var seg = import.AddressTableEntry;
                                    SetTarget(instr, seg!.Rva);
                                    found = true;
                                    break;
                                }
                            }
                        }

                        if (!found)
                        {
                            SetTarget(instr, Inject(current));
                        }
                    }
                }
                instrs[i] = instr;
            }

            // Recompile
            var writer = new CodeWriterImpl();
            var block = new InstructionBlock(writer, instrs, (ulong)(_rva + _offset));

            if (!BlockEncoder.TryEncode(64, block, out string? error, out _, BlockEncoderOptions.None))
            {
                throw new Exception(error);
            }
            body = writer.ToArray();

            Array.Copy(body, 0, _bytes, _offset, body.Length);

            _injected.Add(name, (uint)(_rva + _offset));
            _offset += body.Length;
            return _injected[name];
        }
    }
}

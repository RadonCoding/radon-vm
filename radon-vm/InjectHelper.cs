using AsmResolver;
using AsmResolver.PE.File.Headers;
using Iced.Intel;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection.Emit;
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
            if (_injected.ContainsKey(name))
            {
                return _injected[name];
            }

            Array.Copy(data, 0, _bytes, _offset, data.Length);
            _injected.Add(name, (uint)(_rva + _offset));
            _offset += data.Length;
            return _injected[name];
        }

        public uint Insert(string name, Assembler ass)
        {
            if (_injected.ContainsKey(name))
            {
                return _injected[name];
            }

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

                        bool imp = current.StartsWith("_imp_");

                        bool found = false;

                        foreach (var lib in _compiler.Image.Imports)
                        {
                            foreach (var import in lib.Symbols)
                            {
                                if (import.Name == (imp ? current.Substring(5) : current))
                                {
                                    Console.WriteLine("Found IAT: {0}", current);

                                    var seg = import.AddressTableEntry;

                                    if (imp)
                                    {
                                        _compiler.SetTarget(ref instr, seg!.Rva);
                                    }
                                    else
                                    {
                                        Assembler ass = new Assembler(64);
                                        ass.jmp(seg!.Rva);

                                        ulong thunk = Insert(current, ass);

                                        _compiler.SetTarget(ref instr, thunk);
                                    }
                                    found = true;
                                    break;
                                }
                            }
                        }

                        if (!found)
                        {
                            Console.WriteLine("Injecting: {0}", current);
                            _compiler.SetTarget(ref instr, Inject(current));
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

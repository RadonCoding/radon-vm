using AsmResolver;
using AsmResolver.PE;
using AsmResolver.PE.Code;
using AsmResolver.PE.File;
using AsmResolver.PE.File.Headers;
using AsmResolver.PE.Relocations;
using Iced.Intel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using VeProt_Native.Protections;

namespace VeProt_Native {
    internal class Compiler {
        public PEFile File { get { return _file; } }
        public IPEImage Image { get { return _image; } }
        public InjectHelper Injector { get { return _injector; } }

        private string _filename;

        private PEFile _file;
        private IPEImage _image;

        private Dictionary<uint, uint> _offsets;
        private Dictionary<uint, ulong> _references;

        private Dictionary<int, long> _inserted;

        private List<Adjustment> _adjustments;

        private InjectHelper _injector;

        public Compiler(string filename) {
            _filename = filename;
            _file = PEFile.FromFile(filename);
            _image = PEImage.FromFile(_file);

            _offsets = new Dictionary<uint, uint>();
            _references = new Dictionary<uint, ulong>();

            _inserted = new Dictionary<int, long>();

            _adjustments = new List<Adjustment>();

            PESection inject = new PESection(".veprot0", SectionFlags.ContentCode | SectionFlags.MemoryExecute | SectionFlags.MemoryRead,
                new DataSegment(new byte[InjectHelper.SECTION_SIZE]));
            _file.Sections.Add(inject);
            _file.UpdateHeaders();
            _injector = new InjectHelper(inject.Rva);
        }

        private List<Instruction> GetInstructions(byte[] code, ulong ip) {
            var reader = new ByteArrayCodeReader(code);
            var decoder = Decoder.Create(64, reader, ip);

            var instrs = new List<Instruction>();

            while (reader.CanReadByte) {
                decoder.Decode(out var instr);

                if (!instr.IsInvalid) {
                    instrs.Add(instr);
                }
            }
            return instrs;
        }

        private unsafe void FixRelocs(byte[] image, PESection oldSection, PESection newSection) {
            foreach (var reloc in _image.Relocations) {
                fixed (byte* pImage = image) {
                    uint value = (uint)(*(ulong*)(pImage + reloc.Location.Offset) - _image.ImageBase);
                    var targetSection = _file.GetSectionContainingRva(value);

                    if (targetSection.Rva != oldSection.Rva) continue;

                    uint offset = value - targetSection.Rva;
                    ulong newTarget = _image.ImageBase + newSection.Rva + _offsets[offset];

                    switch (reloc.Type) {
                        case RelocationType.HighLow: {
                                uint* pReloc = (uint*)(pImage + reloc.Location.Offset);
                                *pReloc = (uint)newTarget;
                            }
                            break;
                        case RelocationType.Dir64: {
                                ulong* pReloc = (ulong*)(pImage + reloc.Location.Offset);
                                *pReloc = newTarget;
                            }
                            break;
                    }
                }
            }
        }

        private unsafe void FixExceptions(byte[] image, PESection oldSection, PESection newSection) {
            var exceptions = _file.OptionalHeader.DataDirectories[(int)DataDirectoryIndex.ExceptionDirectory];
            var reader = _file.CreateDataDirectoryReader(exceptions);

            int size = sizeof(RUNTIME_FUNCTION);

            long count = exceptions.Size / size;

            for (int i = 0; i < count; i++) {
                byte[] bytes = new byte[size];
                reader.ReadBytes(bytes, 0, size);

                fixed (byte* pBytes = bytes) {
                    var function = *(RUNTIME_FUNCTION*)pBytes;

                    if (!(function.BeginAddress >= oldSection.Rva && function.BeginAddress < oldSection.Rva + oldSection.GetVirtualSize())) continue;

                    fixed (byte* pImage = image) {
                        uint* pBegin = (uint*)(pImage + reader.Offset);
                        *pBegin = newSection.Rva + _offsets[function.BeginAddress - oldSection.Rva];

                        uint* pEnd = (uint*)(pImage + reader.Offset + sizeof(uint));
                        *pEnd = newSection.Rva + _offsets[function.EndAddress - oldSection.Rva];
                    }
                }
            }
        }

        public void Insert(int offset, byte[] insertion) {
            _adjustments.Add(new Adjustment(offset, insertion));
        }

        public void Replace(int offset, int replace, byte[] insertion) {
            _adjustments.Add(new Adjustment(offset, replace, insertion));
        }

        private void CalcReferences(byte[] code, uint ip, ulong size) {
            var instrs = GetInstructions(code, ip);

            foreach (var instr in instrs) {
                if (instr.IsIPRelative()) {
                    uint src = (uint)(instr.IP - ip);

                    ulong dst = instr.IsIPRelativeMemoryOperand ? instr.IPRelativeMemoryAddress : instr.NearBranchTarget;

                    bool isInSameSection = dst >= ip && dst < ip + size;

                    if (isInSameSection) {
                        uint offset = (uint)(dst - ip);

                        foreach (var adjustment in _adjustments.Where(x => x.Offset <= offset)) {
                            dst += (uint)adjustment.Length;
                        }
                    }

                    uint original = src;

                    foreach (var adjustment in _adjustments.Where(x => x.Offset <= original)) {
                        src += (uint)adjustment.Length;
                    }
                    _references[src] = dst;
                }
            }
        }

        private void FixReferences(byte[] code, uint oldIP, uint newIP, ulong size) {
            var instrs = GetInstructions(code, newIP);

            foreach (var instr in instrs) {
                if (instr.IsIPRelative()) {
                    uint src = (uint)(instr.IP - newIP);

                    ulong dst = instr.IsIPRelativeMemoryOperand ? instr.IPRelativeMemoryAddress : instr.NearBranchTarget;

                    bool isInSameSection = dst >= newIP && dst < newIP + size;

                    if (!isInSameSection) {
                        _references[src] = dst - (newIP - oldIP);
                    }
                }
            }
        }

        private void FixAdjustments(byte[] code, uint oldIP, uint newIP) {
            var instrs = GetInstructions(code, newIP);

            foreach (var instr in instrs) {
                if (instr.IsIPRelative()) {
                    uint src = (uint)(instr.IP - newIP);

                    ulong dst = instr.IsIPRelativeMemoryOperand ? instr.IPRelativeMemoryAddress : instr.NearBranchTarget;

                    if (_adjustments.Any(x => src >= x.Offset && src < x.Offset + x.Length)) {
                        uint original = src;

                        foreach (var adjustment in _adjustments.Where(x => x.Offset <= original)) {
                            dst -= (uint)adjustment.Length;
                        }
                        _references[src] = dst - (newIP - oldIP);
                    }
                }
            }
        }

        private void ApplyAdjustments(ref byte[] code) {
            var adjusted = code.ToList();

            int displacement = 0;

            foreach (var adjustment in _adjustments.OrderBy(x => x.Offset)) {
                int offset = adjustment.Offset + displacement;

                if (adjustment.IsReplace) {
                    for (int i = 0; i < adjustment.Replace; i++) {
                        adjusted[offset + i] = adjustment.Bytes[i];
                    }
                    if (adjustment.Bytes.Length > adjustment.Replace) {
                        adjusted.InsertRange(offset + adjustment.Replace.Value, adjustment.Bytes[adjustment.Replace.Value..]);
                        displacement += adjustment.Bytes.Length - adjustment.Replace.Value;
                    }
                } else {
                    adjusted.InsertRange(offset, adjustment.Bytes);
                    displacement += adjustment.Bytes.Length;
                }
                adjustment.Offset = offset;
            }
            code = adjusted.ToArray();
        }

        private void Reassemble(ref byte[] code, uint ip) {
            var instrs = GetInstructions(code, ip);

            uint[] offsets = new uint[instrs.Count];

            for (int i = 0; i < instrs.Count; i++) {
                var instr = instrs[i];
                uint offset = (uint)(instr.IP - ip);
                offsets[i] = offset;
            }

            for (int i = 0; i < instrs.Count; i++) {
                var instr = instrs[i];

                if (instr.IsIPRelative()) {
                    uint src = (uint)(instr.IP - ip);

                    if (_references.ContainsKey(src)) {
                        ulong dst = _references[src];

                        if (instr.IsIPRelativeMemoryOperand) {
                            if (instr.MemoryDisplSize == 8) {
                                instr.MemoryDisplacement64 = dst;
                            } else {
                                instr.MemoryDisplacement32 = (uint)dst;
                            }
                        } else {
                            switch (instr.Op0Kind) {
                                case OpKind.NearBranch16:
                                    instr.NearBranch16 = (ushort)dst;
                                    break;
                                case OpKind.NearBranch32:
                                    instr.NearBranch32 = (uint)dst;
                                    break;
                                case OpKind.NearBranch64:
                                    instr.NearBranch64 = dst;
                                    break;
                            }
                        }
                    }
                }
                instrs[i] = instr;
            }

            var writer = new CodeWriterImpl();
            var block = new InstructionBlock(writer, instrs, ip);

            if (!BlockEncoder.TryEncode(64, block, out string? error, out _)) {
                throw new Exception(error);
            }
            code = writer.ToArray();
        }

        private unsafe void Process(PESection oldSection) {
            byte[] code = oldSection.WriteIntoArray();

            var last = _file.Sections.Last();
            uint oldSectionRVA = oldSection.Rva;
            uint oldSectionSize = oldSection.GetVirtualSize();
            uint newSectionRVA = (last.Rva + last.GetVirtualSize()).Align(_file.OptionalHeader.SectionAlignment);

            // Find all IP relative instructions to other sections and subtract difference between new and old rva
            FixReferences(code, oldSectionRVA, newSectionRVA, oldSectionSize);
            Reassemble(ref code, newSectionRVA);

            _references.Clear();

            var ass = GetType().Assembly;

            // Main loop for applying all passes
            foreach (var type in ass.GetTypes().Where(x => x.GetInterface("IProtection") != null)) {
                var instance = Activator.CreateInstance(type);
                ((IProtection)instance!).Execute(this, oldSectionRVA, newSectionRVA, code);

                // Calculate the reference targets taking into account the adjustments
                ulong newSectionSize = ((ulong)code.Length).Align(_file.OptionalHeader.SectionAlignment);
                CalcReferences(code, newSectionRVA, newSectionSize);

                // Apply adjustments and fix IP relative instructions in them
                ApplyAdjustments(ref code);
                FixAdjustments(code, oldSectionRVA, newSectionRVA);

                // Assemble the code with adjustments
                Reassemble(ref code, newSectionRVA);

                _references.Clear();
                _adjustments.Clear();
            }

            // NO WAY OF KEEPING TRACK OF OFFSETS SO ALL THE CODE IS USELESS FUCK

            var newSection = new PESection(".veprot1",
                SectionFlags.ContentCode | SectionFlags.MemoryExecute | SectionFlags.MemoryRead,
                new DataSegment(code));
            _file.Sections.Add(newSection);

            _file.UpdateHeaders();

            uint size = oldSection.GetPhysicalSize().Align(_file.OptionalHeader.FileAlignment);
            uint oep = _file.OptionalHeader.AddressOfEntryPoint;

            byte[] replaced = new byte[size];

            if (oep >= oldSection.Rva && oep < oldSection.Rva + oldSection.GetVirtualSize()) {
                uint offset = oep - oldSection.Rva;
                uint nep = newSectionRVA + _offsets[offset];

                var asm = new Assembler(64);
                asm.jmp(nep);

                using (var ms = new MemoryStream()) {
                    asm.Assemble(new StreamCodeWriter(ms), oep);

                    byte[] stub = ms.ToArray();
                    Buffer.BlockCopy(stub, 0, replaced, (int)offset, stub.Length);
                }
            }

            oldSection.Contents = new DataSegment(replaced);

            using (var ms = new MemoryStream()) {
                _file.Write(ms);

                byte[] image = ms.ToArray();
                FixRelocs(image, oldSection, newSection);
                FixExceptions(image, oldSection, newSection);

                _file = PEFile.FromBytes(image);
                _image = PEImage.FromFile(_file);
            }
        }

        public void Protect() {
            var section = _file.GetSectionContainingRva(_file.OptionalHeader.AddressOfEntryPoint);
            Process(section);
        }

        public void Save() {
            var inject = _file.GetSectionContainingRva(_injector.Rva);
            inject.Contents = new DataSegment(_injector.Bytes.ToArray());

            _file.Write(_filename);
        }

        sealed class CodeWriterImpl : CodeWriter {
            private readonly List<byte> _bytes = new List<byte>();
            public override void WriteByte(byte value) => _bytes.Add(value);
            public byte[] ToArray() => _bytes.ToArray();
        }

        sealed class Adjustment {
            public int Offset { get; set; }
            public int? Replace { get; }
            public byte[] Bytes { get; }
            public bool IsReplace => Replace.HasValue;
            public int Length => IsReplace ? Bytes.Length - Replace!.Value : Bytes.Length;

            public Adjustment(int offset, byte[] bytes) {
                Offset = offset;
                Bytes = bytes;
            }

            public Adjustment(int offset, int replace, byte[] bytes) {
                Offset = offset;
                Replace = replace;
                Bytes = bytes;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RUNTIME_FUNCTION {
            public uint BeginAddress;
            public uint EndAddress;
            public Union UnwindData;

            [StructLayout(LayoutKind.Explicit)]
            public struct Union {
                [FieldOffset(0)]
                public uint UnwindInfoAddress;
                [FieldOffset(0)]
                public uint UnwindData;
            }
        }
    }
}

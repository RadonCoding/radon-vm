using AsmResolver;
using AsmResolver.PE;
using AsmResolver.PE.Code;
using AsmResolver.PE.File;
using AsmResolver.PE.File.Headers;
using AsmResolver.PE.Relocations;
using Iced.Intel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using VeProt_Native.Protections;

namespace VeProt_Native {
    internal class Compiler {
        public PEFile File { get { return _file; } }
        public IPEImage Image { get { return _image; } }
        public InjectHelper Injector { get { return _injector; } }

        private string _filename;

        private PEFile _file;
        private IPEImage _image;

        private List<Adjustment> _adjustments;
        private List<Replacement> _replacements;

        private Dictionary<uint, uint> _newOffsets;
        private Dictionary<uint, ulong> _references;

        private InjectHelper _injector;

        public Compiler(string filename) {
            _filename = filename;
            _file = PEFile.FromFile(filename);
            _image = PEImage.FromFile(_file);
            _adjustments = new List<Adjustment>();
            _replacements = new List<Replacement>();
            _newOffsets = new Dictionary<uint, uint>();
            _references = new Dictionary<uint, ulong>();

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

        private unsafe void Assemble(ref byte[] code, uint oldSectionRVA, uint oldSectionSize, uint newSectionRVA) {
            var oldInstrs = GetInstructions(code, oldSectionRVA);

            CalcReferences(oldInstrs, oldSectionRVA, oldSectionSize, newSectionRVA);

            ApplyReplacements(ref code);
            ApplyAdjustments(ref code);

            Reassemble(ref code, newSectionRVA);

            var newInstrs = GetInstructions(code, newSectionRVA);
            FindOffsets(oldInstrs, newInstrs);
        }

        private void CalcReferences(List<Instruction> instrs, uint oldSectionRVA, ulong oldSectionSize, uint newSectionRVA) {
            foreach (var instr in instrs) {
                if (instr.IsIPRelative()) {
                    uint src = (uint)(instr.IP - oldSectionRVA);

                    ulong dst = instr.IsIPRelativeMemoryOperand ? instr.IPRelativeMemoryAddress : instr.NearBranchTarget;

                    if (dst != 0) {
                        bool isInSameSection = dst >= oldSectionRVA && dst < oldSectionRVA + oldSectionSize;

                        if (isInSameSection) {
                            ulong offset = dst - oldSectionRVA;
                            dst -= oldSectionRVA;
                            dst += newSectionRVA;

                            // Calculate dst as a offset and check if it's before or after the adjustment
                            foreach (var adjustment in _adjustments) {
                                if ((uint)adjustment.Offset < offset) {
                                    // If the target address is after the adjustment
                                    dst += (uint)adjustment.Bytes.Length;
                                }
                            }
                        }
                    }
                    _references[src] = dst;
                }
            }
        }

        private void FindOffsets(List<Instruction> oldInstrs, List<Instruction> newInstrs) {
            ulong oldIP = oldInstrs[0].IP;
            ulong newIP = newInstrs[0].IP;

            int offset = 0;

            for (int i = 0, j = 0; i < oldInstrs.Count; i++, j++) {
                // If there's a displacement for the current instruction
                foreach (var adjustment in _adjustments.Where(x => x.Offset == offset)) {
                    int skip = 0;

                    while (skip < adjustment.Bytes.Length) {
                        skip += newInstrs[j++].Length;
                    }
                }
                var oldInstr = oldInstrs[i];
                var newInstr = newInstrs[j];

                uint oldOffset = (uint)(oldInstr.IP - oldIP);
                uint newOffset = (uint)(newInstr.IP - newIP);

                _newOffsets[oldOffset] = newOffset;

                offset += oldInstr.Length;
            }
        }

        private void ApplyReplacements(ref byte[] code) {
            foreach (var replacement in _replacements) {
                Array.Copy(replacement.Bytes, 0, code, replacement.Offset, replacement.Bytes.Length);
            }
        }

        private void ApplyAdjustments(ref byte[] code) {
            var adjusted = code.ToList();

            int displacement = 0;

            foreach (var adjustment in _adjustments.OrderBy(x => x.Offset)) {
                adjusted.InsertRange(adjustment.Offset + displacement, adjustment.Bytes);
                displacement += adjustment.Bytes.Length;
            }
            code = adjusted.ToArray();
        }

        private void Reassemble(ref byte[] code, uint ip) {
            var instrs = GetInstructions(code, ip);

            for (int i = 0; i < instrs.Count; i++) {
                var instr = instrs[i];

                if (instr.IsIPRelative()) {
                    uint src = (uint)(instr.IP - ip);

                    foreach (var adjustment in _adjustments.Where(x => x.Offset < src)) {
                        src -= (uint)adjustment.Bytes.Length;
                    }

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

        private unsafe void FixRelocs(byte[] image, PESection oldSection, PESection newSection) {
            foreach (var reloc in _image.Relocations) {
                fixed (byte* pImage = image) {
                    uint value = (uint)(*(ulong*)(pImage + reloc.Location.Offset) - _image.ImageBase);
                    var targetSection = _file.GetSectionContainingRva(value);

                    if (targetSection.Rva != oldSection.Rva) continue;

                    uint offset = value - targetSection.Rva;
                    ulong newTarget = _image.ImageBase + newSection.Rva + _newOffsets[offset];

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

                GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
                RUNTIME_FUNCTION function = (RUNTIME_FUNCTION)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(RUNTIME_FUNCTION))!;
                handle.Free();

                if (!(function.BeginAddress >= oldSection.Rva && function.BeginAddress < oldSection.Rva + oldSection.GetVirtualSize())) continue;

                fixed (byte* pImage = image) {
                    uint* pBegin = (uint*)(pImage + reader.Offset);
                    *pBegin = newSection.Rva + _newOffsets[function.BeginAddress - oldSection.Rva];

                    uint* pEnd = (uint*)(pImage + reader.Offset + sizeof(uint));
                    *pEnd = newSection.Rva + _newOffsets[function.EndAddress - oldSection.Rva];
                }
            }
        }

        public void Insert(int offset, byte[] insertion) {
            _adjustments.Add(new Adjustment(offset, insertion));
        }

        public void Replace(int offset, int replace, byte[] insertion) {
            _replacements.Add(new Replacement(offset, replace, insertion.Take(replace).ToArray()));

            if (insertion.Length > replace) {
                Insert(offset + replace, insertion.Skip(replace).ToArray());
            }
        }

        private unsafe void Process(PESection oldSection) {
            byte[] code = oldSection.WriteIntoArray();

            var last = _file.Sections.Last();
            uint oldSectionRVA = oldSection.Rva;
            uint oldSectionSize = oldSection.GetVirtualSize();
            uint newSectionRVA = (last.Rva + last.GetVirtualSize()).Align(_file.OptionalHeader.SectionAlignment);

            new Mutation().Execute(this, oldSectionRVA, newSectionRVA, code);
            //new Imports().Execute(this, oldSectionRVA, newSectionRVA, code);

            Assemble(ref code, oldSectionRVA, oldSectionSize, newSectionRVA);

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
                uint nep = newSectionRVA + _newOffsets[offset];

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
            public byte[] Bytes { get; }

            public Adjustment(int offset, byte[] bytes) {
                Offset = offset;
                Bytes = bytes;
            }
        }

        sealed class Replacement {
            public int Offset { get; set; }
            public int Replace { get; set; }
            public byte[] Bytes { get; }

            public Replacement(int offset, int replace, byte[] bytes) {
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

using AsmResolver;
using AsmResolver.PE;
using AsmResolver.PE.File;
using AsmResolver.PE.File.Headers;
using AsmResolver.PE.Relocations;
using Iced.Intel;
using System.Runtime.InteropServices;
using radon_vm.Protections;
using System.Diagnostics;
using System.Drawing;

namespace radon_vm
{
    internal class Compiler
    {
        public PEFile File { get { return _file; } }
        public IPEImage Image { get { return _image; } }
        public InjectHelper Injector { get { return _injector; } }
        public PESection? OldCodeSection { get { return _oldCodeSection; } }
        public PESection? NewCodeSection { get { return _newCodeSection; } }

        private string _filename;

        private PEFile _file;
        private IPEImage _image;

        private Dictionary<uint, uint> _offsets;
        private Dictionary<uint, ulong> _references;

        private Dictionary<int, long> _inserted;

        private List<Adjustment> _adjustments;

        private InjectHelper _injector;

        private PESection? _oldCodeSection;
        private PESection? _newCodeSection;

        public Compiler(string filename)
        {
            _filename = filename;
            _file = PEFile.FromFile(filename);
            _image = PEImage.FromFile(_file);

            _offsets = new Dictionary<uint, uint>();
            _references = new Dictionary<uint, ulong>();

            _inserted = new Dictionary<int, long>();

            _adjustments = new List<Adjustment>();

            PESection inject = new PESection(".radon0", SectionFlags.ContentCode | SectionFlags.ContentInitializedData | SectionFlags.MemoryExecute | SectionFlags.MemoryRead,
                new DataSegment(new byte[InjectHelper.SECTION_SIZE]));
            _file.Sections.Add(inject);
            _file.UpdateHeaders();
            _injector = new InjectHelper(this, inject.Rva);
        }

        public List<Instruction> GetInstructions(byte[] code, ulong ip)
        {
            var reader = new ByteArrayCodeReader(code);
            var decoder = Decoder.Create(64, reader, ip);

            var instrs = new List<Instruction>();

            while (reader.CanReadByte)
            {
                decoder.Decode(out var instr);

                if (!instr.IsInvalid)
                {
                    instrs.Add(instr);
                }
            }
            return instrs;
        }

        private unsafe void FixRelocs(byte[] image, PESection oldSection, PESection newSection)
        {
            foreach (var reloc in _image.Relocations)
            {
                fixed (byte* pImage = image)
                {
                    uint value = (uint)(*(ulong*)(pImage + reloc.Location.Offset) - _image.ImageBase);
                    var targetSection = _file.GetSectionContainingRva(value);

                    if (targetSection.Rva != oldSection.Rva) continue;

                    uint offset = value - targetSection.Rva;
                    ulong newTarget = _image.ImageBase + newSection.Rva + _offsets[offset];

                    switch (reloc.Type)
                    {
                        case RelocationType.HighLow:
                            {
                                uint* pReloc = (uint*)(pImage + reloc.Location.Offset);
                                *pReloc = (uint)newTarget;
                            }
                            break;
                        case RelocationType.Dir64:
                            {
                                ulong* pReloc = (ulong*)(pImage + reloc.Location.Offset);
                                *pReloc = newTarget;
                            }
                            break;
                    }
                }
            }
        }

        private unsafe void FixExceptions(byte[] image, PESection oldSection, PESection newSection)
        {
            var exceptions = _file.OptionalHeader.DataDirectories[(int)DataDirectoryIndex.ExceptionDirectory];
            var reader = _file.CreateDataDirectoryReader(exceptions);

            int size = sizeof(RUNTIME_FUNCTION);

            long count = exceptions.Size / size;

            for (int i = 0; i < count; i++)
            {
                byte[] bytes = new byte[size];
                reader.ReadBytes(bytes, 0, size);

                fixed (byte* pBytes = bytes)
                {
                    var function = *(RUNTIME_FUNCTION*)pBytes;

                    if (!(function.BeginAddress >= oldSection.Rva && function.BeginAddress < oldSection.Rva + oldSection.GetVirtualSize())) continue;

                    fixed (byte* pImage = image)
                    {
                        uint* pBegin = (uint*)(pImage + reader.Offset);
                        *pBegin = newSection.Rva + _offsets[function.BeginAddress - oldSection.Rva];

                        uint* pEnd = (uint*)(pImage + reader.Offset + sizeof(uint));
                        *pEnd = newSection.Rva + _offsets[function.EndAddress - oldSection.Rva];
                    }
                }
            }
        }

        public void Insert(int offset, byte[] insertion)
        {
            _adjustments.Add(new Adjustment(offset, insertion));
        }

        public void Replace(int offset, int replace, byte[] insertion)
        {
            if (insertion.Length < replace)
            {
                int original = insertion.Length;

                // Fill rest of insertion with NOPs
                Array.Resize(ref insertion, replace);

                for (int i = 0; i < replace - original; i++)
                {
                    insertion[original + i] = 0x90;
                }
            }
            _adjustments.Add(new Adjustment(offset, replace, insertion));
        }

        private void CalcReferences(byte[] code, uint ip, ulong size)
        {
            var instrs = GetInstructions(code, ip);

            foreach (var instr in instrs)
            {
                if (instr.IsIPRelative())
                {
                    uint src = (uint)(instr.IP - ip);

                    ulong dst = instr.IsIPRelativeMemoryOperand ? instr.IPRelativeMemoryAddress : instr.NearBranchTarget;

                    bool isInSameSection = dst >= ip && dst < ip + size;

                    if (isInSameSection)
                    {
                        uint offset = (uint)(dst - ip);

                        foreach (var adjustment in _adjustments.Where(x => x.Offset < offset))
                        {
                            dst += (uint)adjustment.Length;
                        }
                    }

                    uint original = src;

                    foreach (var adjustment in _adjustments.Where(x => x.Offset <= original))
                    {
                        src += (uint)adjustment.Length;
                    }
                    _references[src] = dst;
                }
            }
        }

        private void FixReferences(byte[] code, uint oldIP, uint newIP, ulong size)
        {
            var instrs = GetInstructions(code, newIP);

            foreach (var instr in instrs)
            {
                if (instr.IsIPRelative())
                {
                    uint src = (uint)(instr.IP - newIP);

                    ulong dst = instr.IsIPRelativeMemoryOperand ? instr.IPRelativeMemoryAddress : instr.NearBranchTarget;

                    bool isInSameSection = dst >= newIP && dst < newIP + size;

                    if (!isInSameSection)
                    {
                        _references[src] = dst - (newIP - oldIP);
                    }
                }
            }
        }

        private void FixAdjustments(Dictionary<int, Adjustment> inserted, byte[] code, uint oldIP, uint newIP)
        {
            var instrs = GetInstructions(code, newIP);

            foreach (var instr in instrs)
            {
                if (instr.IsIPRelative())
                {
                    uint src = (uint)(instr.IP - newIP);

                    ulong dst = instr.IsIPRelativeMemoryOperand ? instr.IPRelativeMemoryAddress : instr.NearBranchTarget;

                    // If the instruction is part of an adjustment
                    if (inserted.Any(x => src >= x.Key && src < x.Key + x.Value.Bytes.Length))
                    {
                        // The logic here is that we want to ignore the adjustment that this instruction is part of so we add the size of the adjustment to it's beginning
                        foreach (var insert in inserted)
                        {
                            int end = insert.Key + insert.Value.Bytes.Length;

                            if (end < src && end < (uint)(dst - newIP))
                            {
                                dst -= (uint)insert.Value.Length;
                            }
                        }

                        ulong newSectionSize = ((ulong)code.Length).Align(File.OptionalHeader.SectionAlignment);
                        bool isInSameSection = dst >= newIP && dst < newIP + newSectionSize;

                        if (!isInSameSection)
                        {
                            _references[src] = dst - (newIP - oldIP);
                        }
                    }
                }
            }
        }

        private Dictionary<int, Adjustment> ApplyAdjustments(ref byte[] code)
        {
            var adjusted = code.ToList();

            var result = new Dictionary<int, Adjustment>();

            int displacement = 0;

            foreach (var adjustment in _adjustments.OrderBy(x => x.Offset))
            {
                int offset = adjustment.Offset + displacement;

                if (adjustment.IsReplace)
                {
                    for (int i = 0; i < adjustment.Replace; i++)
                    {
                        adjusted[offset + i] = adjustment.Bytes[i];
                    }
                    if (adjustment.Bytes.Length > adjustment.Replace)
                    {
                        adjusted.InsertRange(offset + adjustment.Replace.Value, adjustment.Bytes[adjustment.Replace.Value..]);
                        displacement += adjustment.Length;
                    }
                }
                else
                {
                    adjusted.InsertRange(offset, adjustment.Bytes);
                    displacement += adjustment.Length;
                }
                result.Add(offset, adjustment);
            }
            code = adjusted.ToArray();

            return result;
        }

        public void SetTarget(ref Instruction instr, ulong target)
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

        private void Reassemble(ref byte[] code, uint ip, bool pe = true)
        {
            var instrs = GetInstructions(code, ip);

            uint[] offsets = new uint[instrs.Count];

            for (int i = 0; i < instrs.Count; i++)
            {
                uint offset = (uint)(instrs[i].IP - ip);
                offsets[i] = offset;
            }

            for (int i = 0; i < instrs.Count; i++)
            {
                var instr = instrs[i];

                if (instr.IsIPRelative())
                {
                    uint src = (uint)(instr.IP - ip);

                    if (_references.ContainsKey(src))
                    {
                        ulong dst = _references[src];
                        SetTarget(ref instr, dst);
                    }
                }
                instrs[i] = instr;
            }

            var writer = new CodeWriterImpl();
            var block = new InstructionBlock(writer, instrs, ip);

            if (!BlockEncoder.TryEncode(64, block, out string? error, out var result, pe ? BlockEncoderOptions.ReturnNewInstructionOffsets : BlockEncoderOptions.None))
            {
                throw new Exception(error);
            }

            if (pe)
            {
                // Find new offsets
                foreach (var kv in _offsets)
                {
                    for (int i = 0; i < result.NewInstructionOffsets.Length; i++)
                    {
                        uint oldOffset = offsets[i];
                        uint newOffset = result.NewInstructionOffsets[i];

                        if (kv.Value == oldOffset)
                        {
                            _offsets[kv.Key] = newOffset;
                        }
                    }
                }
            }
            code = writer.ToArray();
        }

        private void Execute(IProtection protection, uint oldSectionRVA, uint newSectionRVA, ref byte[] code, bool pe = true)
        {
            protection.Execute(this, oldSectionRVA, newSectionRVA, code);

            // Calculate the reference targets taking into account the adjustments
            ulong newSectionSize = ((ulong)code.Length).Align(_file.OptionalHeader.SectionAlignment);
            CalcReferences(code, newSectionRVA, newSectionSize);

            if (pe)
            {
                // Find all adjustments inserted before the offsets
                foreach (var kv in _offsets)
                {
                    foreach (var adjustment in _adjustments)
                    {
                        // If the adjustment was before or at the instruction start we add the length
                        if (adjustment.Offset <= kv.Value)
                        {
                            _offsets[kv.Key] += (uint)adjustment.Length;
                        }
                    }
                }
            }

            // Apply adjustments and fix IP relative instructions in them
            var inserted = ApplyAdjustments(ref code);
            FixAdjustments(inserted, code, oldSectionRVA, newSectionRVA);

            // Assemble the code with adjustments
            Reassemble(ref code, newSectionRVA, pe);

            _references.Clear();
            _adjustments.Clear();
        }

        public void Obfuscate(ref byte[] code, uint ip)
        {
            Execute(new Mutation(), ip, ip, ref code, false);
        }

        private unsafe void Process()
        {
            byte[] code = _oldCodeSection!.WriteIntoArray();

            var last = _file.Sections.Last();
            uint oldSectionRVA = _oldCodeSection!.Rva;
            uint oldSectionSize = _oldCodeSection!.GetVirtualSize();
            uint newSectionRVA = (last.Rva + last.GetVirtualSize()).Align(_file.OptionalHeader.SectionAlignment);

            var oldInstrs = GetInstructions(code, oldSectionRVA);

            foreach (var instr in oldInstrs)
            {
                uint offset = (uint)(instr.IP - oldSectionRVA);
                _offsets[offset] = offset;
            }

            // Find all IP relative instructions to other sections and subtract difference between new and old rva
            FixReferences(code, oldSectionRVA, newSectionRVA, oldSectionSize);
            Reassemble(ref code, newSectionRVA);

            _references.Clear();

            Execute(new Virtualization(), oldSectionRVA, newSectionRVA, ref code);
            Execute(new Mutation(), oldSectionRVA, newSectionRVA, ref code);

            _newCodeSection = new PESection(".radon1",
                SectionFlags.ContentCode | SectionFlags.MemoryExecute | SectionFlags.MemoryRead,
                new DataSegment(code));
            _file.Sections.Add(_newCodeSection);

            _file.UpdateHeaders();

            uint size = _oldCodeSection!.GetPhysicalSize().Align(_file.OptionalHeader.FileAlignment);
            uint oep = _file.OptionalHeader.AddressOfEntryPoint;

            byte[] replaced = new byte[size];

            if (oep >= _oldCodeSection!.Rva && oep < _oldCodeSection!.Rva + _oldCodeSection!.GetVirtualSize())
            {
                uint offset = oep - _oldCodeSection!.Rva;
                uint nep = newSectionRVA + _offsets[offset];

                var asm = new Assembler(64);
                asm.jmp(nep);

                using (var ms = new MemoryStream())
                {
                    asm.Assemble(new StreamCodeWriter(ms), oep);

                    byte[] stub = ms.ToArray();
                    Buffer.BlockCopy(stub, 0, replaced, (int)offset, stub.Length);
                }
            }

            _oldCodeSection!.Contents = new DataSegment(replaced);

            using (var ms = new MemoryStream())
            {
                _file.Write(ms);

                byte[] image = ms.ToArray();
                FixRelocs(image, _oldCodeSection, _newCodeSection);
                FixExceptions(image, _oldCodeSection, _newCodeSection);

                _file = PEFile.FromBytes(image);
                _image = PEImage.FromFile(_file);
            }
        }

        public void Protect()
        {
            _oldCodeSection = _file.GetSectionContainingRva(_file.OptionalHeader.AddressOfEntryPoint);
            Process();
        }

        public void Save()
        {
            var inject = _file.GetSectionContainingRva(_injector.Rva);
            inject.Contents = new DataSegment(_injector.Bytes.ToArray());
            _file.Write(_filename);
        }

        sealed class Adjustment
        {
            public int Offset { get; }
            public int? Replace { get; }
            public byte[] Bytes { get; }
            public bool IsReplace => Replace.HasValue;
            public int Length => IsReplace ? Bytes.Length - Replace!.Value : Bytes.Length;

            public Adjustment(int offset, byte[] bytes)
            {
                Offset = offset;
                Bytes = bytes;
            }

            public Adjustment(int offset, int replace, byte[] bytes)
            {
                Offset = offset;
                Replace = replace;
                Bytes = bytes;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RUNTIME_FUNCTION
        {
            public uint BeginAddress;
            public uint EndAddress;
            public Union UnwindData;

            [StructLayout(LayoutKind.Explicit)]
            public struct Union
            {
                [FieldOffset(0)]
                public uint UnwindInfoAddress;
                [FieldOffset(0)]
                public uint UnwindData;
            }
        }
    }
}

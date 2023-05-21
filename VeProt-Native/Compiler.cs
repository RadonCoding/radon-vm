using AsmResolver;
using AsmResolver.PE;
using AsmResolver.PE.File;
using AsmResolver.PE.File.Headers;
using AsmResolver.PE.Relocations;
using Iced.Intel;
using System.Diagnostics;
using System.Reflection;

namespace VeProt_Native {
    internal class Compiler {
        public const int HEXBYTES_COLUMN_BYTE_LENGTH = 10;

        public PEFile File { get { return _file; } }
        public IPEImage Image { get { return _image; } }

        private string _filename;

        private PEFile _file;
        private IPEImage _image;

        private List<Adjustment> _adjustments;
        private Dictionary<PESection, PESection> _newSections;

        public Compiler(string filename) {
            _filename = filename;
            _file = PEFile.FromFile(filename);
            _image = PEImage.FromFile(_file);
            _adjustments = new List<Adjustment>();
            _newSections = new Dictionary<PESection, PESection>();
        }

        private unsafe void Assemble(uint oldSectionRVA, ulong oldSectionSize, uint newSectionRVA, ref byte[] code) {
            var reader = new ByteArrayCodeReader(code);
            var decoder = Decoder.Create(64, reader, oldSectionRVA);

            var instrs = new List<Instruction>();

            while (reader.CanReadByte) {
                decoder.Decode(out var instr);

                if (!instr.IsInvalid) {
                    if (instr.IsIPRelative()) {
                        int src = (int)(instr.IP - oldSectionRVA);
                        ulong target = 0;

                        if (instr.IsIPRelativeMemoryOperand) {
                            target = instr.IPRelativeMemoryAddress;
                        } else {
                            target = instr.NearBranchTarget;
                        }

                        bool isInSameSection = target >= oldSectionRVA && target < oldSectionRVA + oldSectionSize;

                        foreach (var adjustment in _adjustments) {
                            // If it's in a different section and IP is after adjustment
                            if (!isInSameSection) {
                                if (src > adjustment.Offset) {
                                    if (instr.IsIPRelativeMemoryOperand) {
                                        instr.MemoryDisplacement64 -= (ulong)adjustment.Displacement;
                                    } else {
                                        instr.NearBranch64 -= (ulong)adjustment.Displacement;
                                    }
                                }
                            } else {
                                int dst = (int)(target - oldSectionRVA);

                                if (instr.IsIPRelativeMemoryOperand) {
                                    // If the IP is after the adjustment and the target is before
                                    if (src > adjustment.Offset && dst < adjustment.Offset) {
                                        instr.MemoryDisplacement64 -= (ulong)adjustment.Displacement;
                                    }
                                    // If the IP is before the adjustment and the target is after
                                    else if (src < adjustment.Offset && dst > adjustment.Offset) {
                                        instr.MemoryDisplacement64 += (ulong)adjustment.Displacement;
                                    }
                                } else {
                                    // If the IP is after the adjustment and the target is before
                                    if (src > adjustment.Offset && dst < adjustment.Offset) {
                                        switch (instr.Op0Kind) {
                                            case OpKind.NearBranch16:
                                                instr.NearBranch16 -= (ushort)adjustment.Displacement;
                                                break;
                                            case OpKind.NearBranch32:
                                                instr.NearBranch32 -= (uint)adjustment.Displacement;
                                                break;
                                            case OpKind.NearBranch64:
                                                instr.NearBranch64 -= (ulong)adjustment.Displacement;
                                                break;
                                        }
                                    }
                                    // If the IP is before the adjustment and the target is after
                                    else if (src < adjustment.Offset && dst > adjustment.Offset) {
                                        switch (instr.Op0Kind) {
                                            case OpKind.NearBranch16:
                                                instr.NearBranch16 += (ushort)adjustment.Displacement;
                                                break;
                                            case OpKind.NearBranch32:
                                                instr.NearBranch32 += (uint)adjustment.Displacement;
                                                break;
                                            case OpKind.NearBranch64:
                                                instr.NearBranch64 += (ulong)adjustment.Displacement;
                                                break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    instrs.Add(instr);
                }
            }

            var writer = new CodeWriterImpl();
            var block = new InstructionBlock(writer, instrs, newSectionRVA);

            if (!BlockEncoder.TryEncode(64, block, out string? error, out _)) {
                throw new Exception(error);
            }

            code = writer.ToArray();

            reader = new ByteArrayCodeReader(code);
            decoder = Decoder.Create(64, reader, newSectionRVA);

            int index = 0;

            // Find instructions that have had their size changed and then add a adjustment
            while (index < instrs.Count) {
                decoder.Decode(out var instr);

                int oldLength = instrs[index].Length;
                int newLength = instr.Length;

                if (newLength != oldLength) {
                    int delta = newLength - oldLength;
                    int offset = (int)(instrs[index].IP - oldSectionRVA) + oldLength + delta;

                    _adjustments.Add(new Adjustment(oldSectionRVA, offset, delta));
                }
                index++;
            }

            _adjustments = _adjustments.OrderBy(x => x.Offset).ToList();

            List<byte> adjusted = code.ToList();

            // Applies all the adjustments
            foreach (var first in _adjustments) {
                if (first.Rva != oldSectionRVA) continue;

                int offset = first.Offset;

                foreach (var second in _adjustments) {
                    if (first.Offset > second.Offset) {
                        offset += second.Displacement;
                    }
                }

                if (first.Bytes is null) continue;

                adjusted.InsertRange(offset, first.Bytes);
            }
            code = adjusted.ToArray();
        }

        private unsafe void FixRelocs(byte[] image) {
            foreach (var reloc in _image.Relocations) {
                uint oep = _file.OptionalHeader.AddressOfEntryPoint;

                foreach (var entry in _newSections) {
                    var oldSection = entry.Key;
                    var newSection = entry.Value;

                    if (oep >= oldSection.Rva && oep < oldSection.Rva + oldSection.GetVirtualSize()) {
                        fixed (byte* pImage = image) {
                            uint value = (uint)(*(ulong*)(pImage + reloc.Location.Offset) - _image.ImageBase);
                            var targetSection = _file.GetSectionContainingRva(value);

                            if (targetSection.Rva == oldSection.Rva) {
                                // Offset of the target address in the section
                                int offset = (int)(value - targetSection.Rva);

                                int displacement = 0;

                                foreach (var adjustment in _adjustments) {
                                    if (adjustment.Rva == oldSection.Rva) {
                                        // If the target address comes after the adjustment offset
                                        if ((offset + displacement) > adjustment.Offset) {
                                            displacement += adjustment.Displacement;
                                        }
                                    }
                                }

                                Console.WriteLine();

                                Console.WriteLine("[*] Target section: {0}", targetSection.Name);
                                Console.WriteLine("[*] Reloc address: 0x{0}", (_image.ImageBase + reloc.Location.Rva).ToString("X16"));
                                Console.WriteLine("[*] Target address: 0x{0}", (_image.ImageBase + value).ToString("X16"));
                                Console.WriteLine("[*] New target address: 0x{0}", (_image.ImageBase + value - oldSection.Rva + newSection.Rva).ToString("X16"));
                                Console.WriteLine("[*] New adjusted target address: 0x{0}", ((long)(_image.ImageBase + value - oldSection.Rva + newSection.Rva) + displacement).ToString("X16"));

                                switch (reloc.Type) {
                                    case RelocationType.HighLow: {
                                            int* pReloc = (int*)(pImage + reloc.Location.Offset);
                                            *pReloc -= (int)oldSection.Rva;
                                            *pReloc += (int)newSection.Rva;
                                            *pReloc += displacement;
                                        }
                                        break;
                                    case RelocationType.Dir64: {
                                            long* pReloc = (long*)(pImage + reloc.Location.Offset);
                                            *pReloc -= oldSection.Rva;
                                            *pReloc += newSection.Rva;
                                            *pReloc += displacement;
                                        }
                                        break;
                                }
                            }
                        }
                    }
                }
            }
        }

        public void Insert(uint rva, int offset, byte[] insertion) {
            _adjustments.Add(new Adjustment(rva, offset, insertion.Length, insertion));
        }

        private unsafe void Process(PESection oldSection) {
            byte[] newCode = oldSection.WriteIntoArray();

            var last = _file.Sections.Last();
            uint oldSectionRVA = oldSection.Rva;
            uint oldSectionSize = oldSection.GetVirtualSize();
            uint newSectionRVA = (last.Rva + last.GetVirtualSize()).Align(_file.OptionalHeader.SectionAlignment);

            var ass = GetType().Assembly;

            foreach (var type in ass.GetTypes().Where(x => x.GetInterface("IProtection") != null)) {
                var instance = Activator.CreateInstance(type);
                MethodInfo? info = type.GetMethod("Execute");
                info?.Invoke(instance, new object[] { this, oldSectionRVA, newSectionRVA, newCode });
            }

            Assemble(oldSectionRVA, oldSectionSize, newSectionRVA, ref newCode);

            var newSection = new PESection($".veprot{_newSections.Count}",
                SectionFlags.ContentCode | SectionFlags.MemoryExecute | SectionFlags.MemoryRead,
                new DataSegment(newCode));
            _file.Sections.Add(newSection);

            _file.UpdateHeaders();

            uint size = oldSection.GetPhysicalSize().Align(_file.OptionalHeader.FileAlignment);
            uint oep = _file.OptionalHeader.AddressOfEntryPoint;

            byte[] oldCode = new byte[size];

            if (oep >= oldSection.Rva && oep < oldSection.Rva + oldSection.GetVirtualSize()) {
                uint offset = oep - oldSection.Rva;
                int nep = (int)(newSection.Rva + offset);

                foreach (var adjustment in _adjustments) {
                    if (adjustment.Rva == oldSection.Rva) {
                        if (offset > adjustment.Offset) {
                            nep += adjustment.Displacement;
                        }
                    }
                }

                var asm = new Assembler(64);
                asm.jmp((uint)nep);

                using (var ms = new MemoryStream()) {
                    asm.Assemble(new StreamCodeWriter(ms), oep);

                    byte[] stub = ms.ToArray();
                    Buffer.BlockCopy(stub, 0, oldCode, (int)offset, stub.Length);
                }
            }

            oldSection.Contents = new DataSegment(oldCode);

            _newSections.Add(oldSection, newSection);
        }

        public void Protect() {
            var sections = _file.Sections.Where(x => x.IsContentCode).ToArray();

            foreach (PESection section in sections) {
                Process(section);
            }
        }

        public void Save() {
            using (var ms = new MemoryStream()) {
                _file.Write(ms);

                byte[] image = ms.ToArray();
                FixRelocs(image);

                _file = PEFile.FromBytes(image);
                _image = PEImage.FromFile(_file);
            }
            _file.Write(_filename);
        }

        sealed class CodeWriterImpl : CodeWriter {
            private readonly List<byte> bytes = new List<byte>();
            public override void WriteByte(byte value) => bytes.Add(value);
            public byte[] ToArray() => bytes.ToArray();
        }

        sealed class Adjustment {
            public uint Rva { get; }
            public int Offset { get; set; }
            public int Displacement { get; }
            public byte[]? Bytes { get; }

            public Adjustment(uint rva, int offset, int displacement) {
                Rva = rva;
                Offset = offset;
                Displacement = displacement;
            }

            public Adjustment(uint rva, int offset, int displacement, byte[] bytes) {
                Rva = rva;
                Offset = offset;
                Displacement = displacement;
                Bytes = bytes;
            }
        }
    }
}

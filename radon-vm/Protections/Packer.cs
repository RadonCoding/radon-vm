using AsmResolver.PE.File;
using AsmResolver.PE;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AsmResolver.PE.File.Headers;
using AsmResolver;
using Iced.Intel;

namespace radon_vm.Protections
{
    internal class Packer
    {
        private const string RUNTIME = "radon-vm.runtime.packer.exe";
        private const int KEY_SIZE = 32;

        public static void Execute(uint rva, byte[] binary, string filename)
        {
            var src = PEFile.FromBytes(binary);

            var runtime = new Runtime();
            var target = src.GetSectionContainingRva(rva);
            byte[] code = target.WriteIntoArray();

            var reader = new ByteArrayCodeReader(code);
            var decoder = Decoder.Create(64, reader, target.Rva);

            while (reader.CanReadByte)
            {
                decoder.Decode(out var instr);

                if (!instr.IsInvalid && instr.Mnemonic != Mnemonic.Int3)
                {
                    int offset = (int)(instr.IP - target.Rva);
                    byte[] raw = code.Skip(offset).Take(instr.Length).ToArray();

                    var rt = new RuntimeInstruction(raw.ToList());

                    runtime.AddInstruction(instr.IP, rt);

                    Array.Fill(code, (byte)0xCC, offset, instr.Length);
                }
            }

            target!.Contents = new DataSegment(code);

            using (var ms = new MemoryStream())
            {
                src.Write(ms);
                var payload = new Payload(ms.ToArray().ToList());

                File.Copy(RUNTIME, filename, true);

                var dst = PEFile.FromFile(filename);

                PESection section0 = new PESection(".radon0", SectionFlags.ContentInitializedData | SectionFlags.MemoryRead,
                    new DataSegment(runtime.Serialize()));
                dst.Sections.Add(section0);

                PESection section1 = new PESection(".radon1", SectionFlags.ContentInitializedData | SectionFlags.MemoryRead, 
                    new DataSegment(payload.Serialize()));
                dst.Sections.Add(section1);

                dst.UpdateHeaders();
                dst.Write(filename);

                Compiler compiler = new Compiler(filename, false);
                compiler.Protect();
                compiler.Save();
            }
        }

        internal class Runtime
        {
            private Dictionary<ulong, RuntimeInstruction> _runtimeInstrs = new Dictionary<ulong, RuntimeInstruction>();
            private ulong _oldRVA = 0;

            public byte[] Serialize()
            {
                List<byte> serialized = new List<byte>();

                ulong instrCount = (ulong)_runtimeInstrs.Count;
                serialized.AddRange(BitConverter.GetBytes(instrCount));

                foreach (var kvp in _runtimeInstrs)
                {
                    ulong rva = kvp.Key;
                    serialized.AddRange(BitConverter.GetBytes(rva));

                    byte[] instrBytes = kvp.Value.GetBytes().ToArray();
                    ulong instrSize = (ulong)instrBytes.Length;
                    serialized.AddRange(BitConverter.GetBytes(instrSize));
                    serialized.AddRange(instrBytes);

                    byte[] keyBytes = kvp.Value.GetKey().ToArray();
                    ulong keySize = (ulong)keyBytes.Length;
                    serialized.AddRange(BitConverter.GetBytes(keySize));
                    serialized.AddRange(keyBytes);
                }

                ulong oldRVASize = sizeof(ulong);
                serialized.AddRange(BitConverter.GetBytes(oldRVASize));
                serialized.AddRange(BitConverter.GetBytes(_oldRVA));

                return serialized.ToArray();
            }

            public void AddInstruction(ulong rva, RuntimeInstruction runtimeInstr)
            {
                _runtimeInstrs.Add(rva, runtimeInstr);
            }

            public bool HasInstruction(ulong rva)
            {
                return _runtimeInstrs.ContainsKey(rva);
            }

            public RuntimeInstruction GetInstruction(ulong rva)
            {
                return _runtimeInstrs[rva];
            }

            public ulong GetOldRVA()
            {
                if (_oldRVA != 0)
                {
                    ulong oldRVA = _oldRVA;
                    _oldRVA = 0;
                    return oldRVA;
                }
                return 0;
            }

            public void SetOldRVA(ulong rva)
            {
                _oldRVA = rva;
            }
        }

        internal class RuntimeInstruction
        {
            private List<byte> _bytes;
            private List<byte> _key;

            public void Crypt()
            {
                for (int i = 0; i < _bytes.Count; i++)
                {
                    _bytes[i] ^= _key[i % _key.Count];
                }
            }

            public IReadOnlyList<byte> GetBytes()
            {
                return _bytes.AsReadOnly();
            }

            public IReadOnlyList<byte> GetKey()
            {
                return _key.AsReadOnly();
            }

            public RuntimeInstruction(List<byte> bytes)
            {
                _bytes = bytes;

                Random random = new Random();
                _key = new List<byte>(KEY_SIZE);

                for (int i = 0; i < KEY_SIZE; i++)
                {
                    _key.Add((byte)random.Next(0, 256));
                }
                Crypt();
            }

            public RuntimeInstruction(List<byte> bytes, List<byte> key)
            {
                _bytes = bytes;
                _key = key;
            }

            public RuntimeInstruction()
            {
                _bytes = new List<byte>();
                _key = new List<byte>();
            }
        }

        internal class Payload
        {
            private List<byte> _bytes;
            private List<byte> _key;

            public void Crypt()
            {
                for (int i = 0; i < _bytes.Count; i++)
                {
                    _bytes[i] ^= _key[i % _key.Count];
                }
            }

            public IReadOnlyList<byte> GetBytes()
            {
                return _bytes.AsReadOnly();
            }

            public IReadOnlyList<byte> GetKey()
            {
                return _key.AsReadOnly();
            }

            public byte[] Serialize()
            {
                List<byte> serialized = new List<byte>();

                int bytesSize = _bytes.Count;
                serialized.AddRange(BitConverter.GetBytes(bytesSize));
                serialized.AddRange(_bytes);

                int keySize = _key.Count;
                serialized.AddRange(BitConverter.GetBytes(keySize));
                serialized.AddRange(_key);

                return serialized.ToArray();
            }

            public Payload(List<byte> bytes)
            {
                _bytes = bytes;

                Random random = new Random();
                _key = new List<byte>(KEY_SIZE);

                for (int i = 0; i < KEY_SIZE; i++)
                {
                    _key.Add((byte)random.Next(0, 256));
                }
                Crypt();
            }

            public Payload()
            {
                _bytes = new List<byte>();
                _key = new List<byte>();
            }
        }
    }
}

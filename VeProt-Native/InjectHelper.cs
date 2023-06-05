using Iced.Intel;
using System.Runtime.InteropServices;
using static Iced.Intel.AssemblerRegisters;

namespace VeProt_Native {
    internal class InjectHelper {
        public static int SECTION_SIZE = 0x1000;

        public Dictionary<string, uint> Injected { get { return _injected; } }
        public byte[] Bytes { get { return _bytes; } }

        public uint Rva { get { return _rva; } }

        private Dictionary<string, uint> _injected;
        private byte[] _bytes;

        private uint _rva;
        private int _offset;

        public InjectHelper(uint rva) {
            _injected = new Dictionary<string, uint>();
            _bytes = new byte[SECTION_SIZE];
            _rva = rva;
        }

        public uint GetPrologue() {
            const string name = "Prologue";

            if (Injected.ContainsKey(name)) {
                return Injected[name];
            }

            Assembler ass = new Assembler(64);
            ass.sub(rsp, 96);

            ass.mov(__[rsp - 8], rbx);
            ass.mov(__[rsp - 16], rcx);
            ass.mov(__[rsp - 24], rdx);
            ass.mov(__[rsp - 32], rsi);
            ass.mov(__[rsp - 40], rdi);
            ass.mov(__[rsp - 48], r8);
            ass.mov(__[rsp - 56], r9);
            ass.mov(__[rsp - 64], r10);
            ass.mov(__[rsp - 72], r11);
            ass.mov(__[rsp - 80], r12);
            ass.mov(__[rsp - 88], r13);
            ass.mov(__[rsp - 96], r14);
            ass.mov(__[rsp - 104], r15);

            ass.add(rsp, 96);

            ass.ret();

            return Insert(name, ass);
        }

        public uint GetEpilogue() {
            const string name = "Epilogue";

            if (Injected.ContainsKey(name)) {
                return Injected[name];
            }

            Assembler ass = new Assembler(64);
            ass.sub(rsp, 96);

            ass.mov(r15, __[rsp - 104]);
            ass.mov(r14, __[rsp - 96]);
            ass.mov(r13, __[rsp - 88]);
            ass.mov(r12, __[rsp - 80]);
            ass.mov(r11, __[rsp - 72]);
            ass.mov(r10, __[rsp - 64]);
            ass.mov(r9, __[rsp - 56]);
            ass.mov(r8, __[rsp - 48]);
            ass.mov(rdi, __[rsp - 40]);
            ass.mov(rsi, __[rsp - 32]);
            ass.mov(rdx, __[rsp - 24]);
            ass.mov(rcx, __[rsp - 16]);
            ass.mov(rbx, __[rsp - 8]);

            ass.add(rsp, 96);

            ass.ret();

            return Insert(name, ass);
        }

        private uint Insert(string name, Assembler ass) {
            using (var ms = new MemoryStream()) {
                ass.Assemble(new StreamCodeWriter(ms), (uint)(_rva + _offset));
                byte[] assembled = ms.ToArray();
                Array.Copy(assembled, 0, _bytes, _offset, assembled.Length);
                _injected.Add(name, (uint)(_rva + _offset));
                _offset += assembled.Length;
                return _injected[name];
            }
        }

        public unsafe uint Inject(string name) {
            if (_injected.ContainsKey(name)) {
                return _injected[name];
            }

            IntPtr src = Runtime.GetFunction(name);
            int len = Runtime.GetSize(name);

            byte[] body = new byte[len];
            Marshal.Copy(src, body, 0, body.Length);

            Array.Copy(body, 0, _bytes, _offset, body.Length);

            _injected.Add(name, (uint)(_rva + _offset));

            _offset += body.Length;

            return _injected[name];
        }
    }
}

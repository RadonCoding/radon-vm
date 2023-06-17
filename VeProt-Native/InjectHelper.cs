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

        public uint Insert(string name, byte[] data) {
            Array.Copy(data, 0, _bytes, _offset, data.Length);
            _injected.Add(name, (uint)(_rva + _offset));
            _offset += data.Length;
            return _injected[name];
        }

        public uint Insert(string name, Assembler ass) {
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
            uint len = Runtime.GetSize(name);

            byte[] body = new byte[len];
            Marshal.Copy(src, body, 0, body.Length);

            Array.Copy(body, 0, _bytes, _offset, body.Length);

            _injected.Add(name, (uint)(_rva + _offset));
            _offset += body.Length;
            return _injected[name];
        }
    }
}

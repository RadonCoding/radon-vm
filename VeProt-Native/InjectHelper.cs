using AsmResolver;
using AsmResolver.PE;
using AsmResolver.PE.File;
using System.Runtime.InteropServices;

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

using Iced.Intel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace radon_vm
{
    sealed class CodeWriterImpl : CodeWriter
    {
        private readonly List<byte> _bytes = new List<byte>();
        public override void WriteByte(byte value) => _bytes.Add(value);
        public byte[] ToArray() => _bytes.ToArray();
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace radon_vm
{
    internal class Util
    {
        private static readonly string _chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        private static readonly Random _rng = new Random();

        public static string GenerateSectionName()
        {
            var sb = new StringBuilder();
            sb.Append('.');

            for (int i = 0; i < _rng.Next(1, 7); i++)
            {
                sb.Append(_chars[_rng.Next(_chars.Length)]);
            }
            return sb.ToString();
        }
    }
}

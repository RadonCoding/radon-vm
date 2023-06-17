using System.Runtime.InteropServices;

namespace VeProt_Native {
    public static class Runtime {
        const string DLL_NAME = "VeProt-Native.Runtime.dll";

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        public static unsafe IntPtr GetFunction(string name) {
            var symbol = GetSymbol(name);
            byte* lib = (byte*)NativeLibrary.Load(DLL_NAME);
            return new IntPtr(lib + symbol.Address);
        }

        private static IReadOnlyCollection<SymbolInfo> GetAllSymbolsFromPdb(string path) {
            var symbols = new List<SymbolInfo>();

            var process = GetCurrentProcess();

            if (SymInitialize(process, null, false)) {
                var callback = new SymEnumSymbolsProc((pSymInfo, SymbolSize, UserContext) => {
                    symbols.Add(pSymInfo);
                    return true;
                });

                var module = SymLoadModuleEx(process, IntPtr.Zero, path, null, 0, 0, IntPtr.Zero, 0);

                if (module != 0) {
                    SymEnumSymbols(process, module, null, callback, IntPtr.Zero);
                    SymUnloadModule64(process, module);
                }
                SymCleanup(process);
            }
            return symbols;
        }

        private static SymbolInfo GetSymbol(string name) {
            var symbols = GetAllSymbolsFromPdb(DLL_NAME);
            return symbols.First(x => x.Name == name);
        }

        public static uint GetSize(string name) {
            var symbol = GetSymbol(name);
            return symbol.Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SymbolInfo {
            public uint SizeOfStruct;
            public uint TypeIndex;
            public long Reserved1;
            public long Reserved2;
            public uint Index;
            public uint Size;
            public ulong ModBase;
            public uint Flags;
            public ulong Value;
            public ulong Address;
            public uint Register;
            public uint Scope;
            public uint Tag;
            public uint NameLen;
            public uint MaxNameLen;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 1)]
            public string Name;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate bool SymEnumSymbolsProc(SymbolInfo pSymInfo, ulong SymbolSize, IntPtr UserContext);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("dbghelp.dll", CharSet = CharSet.Ansi)]
        private static extern long SymLoadModuleEx(IntPtr hProcess, IntPtr hFile,
            string ImageName, string? ModuleName, long BaseOfDll,
            int DllSize, IntPtr Data, int Flags);

        [DllImport("dbghelp.dll")]
        private static extern bool SymUnloadModule64(IntPtr hProcess, long BaseOfDll);

        [DllImport("dbghelp.dll", CharSet = CharSet.Ansi)]
        private static extern bool SymInitialize(IntPtr hProcess, string? UserSearchPath,
            bool fInvadeProcess);

        [DllImport("dbghelp.dll")]
        private static extern bool SymCleanup(IntPtr hProcess);

        [DllImport("dbghelp.dll", CharSet = CharSet.Ansi)]
        private static extern bool SymEnumSymbols(IntPtr hProcess, long BaseOfDll,
            string? Mask, SymEnumSymbolsProc EnumSymbolsCallback, IntPtr UserContext);
    }
}

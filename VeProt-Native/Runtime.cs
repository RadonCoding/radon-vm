using System.Diagnostics.SymbolStore;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.DiaSymReader;

namespace VeProt_Native {
    public static class Runtime {
        const string DLL_NAME = "VeProt-Native.Runtime.dll";
        const string PDB_NAME = "VeProt-Native.Runtime.pdb";

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int Hash(IntPtr pInput);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        public static IntPtr GetFunction(string name) {
            IntPtr lib = NativeLibrary.Load(DLL_NAME);
            IntPtr func = NativeLibrary.GetExport(lib, name);
            return func;
        }

        private static IReadOnlyCollection<SymbolInfo> GetAllSymbolsFromPdb(string path) {
            var symbols = new List<SymbolInfo>();

            var process = GetCurrentProcess();

            if (SymInitialize(process, null, false)) {
                var callback = new SymEnumSymbolsProc((pSymInfo, SymbolSize, UserContext) =>
                {
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

        public static int GetSize(string name) {
            var symbols = GetAllSymbolsFromPdb(DLL_NAME);
            return symbols.First(x => x.Name == name).Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SymbolInfo {
            public int SizeOfStruct;
            public int TypeIndex;
            public long Reserved1;
            public long Reserved2;
            public int Index;
            public int Size;
            public long ModBase;
            public int Flags;
            public long Value;
            public long Address;
            public int Register;
            public int Scope;
            public int Tag;
            public int NameLen;
            public int MaxNameLen;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 1024)]
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

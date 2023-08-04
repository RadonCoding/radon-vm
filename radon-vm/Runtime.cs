using AsmResolver;
using AsmResolver.PE.File;
using System.Runtime.InteropServices;
using System.Xml.Linq;

namespace radon_vm {
    public static class Runtime {
        const string DLL_NAME = "radon-vm.runtime.dll";

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        public static unsafe IntPtr GetFunction(string name) {
            var symbol = GetSymbol(name);
            byte* lib = (byte*)NativeLibrary.Load(DLL_NAME);
            return new IntPtr(lib + symbol.Address - symbol.ModBase);
        }

        public static PESection GetSection(string name)
        {
            var symbol = GetSymbol(name);
            var section = GetSection((uint)(symbol.Address - symbol.ModBase));
            return section;
        }

        public static PESection GetSection(uint address)
        {
            var file = PEFile.FromFile(DLL_NAME);
            var section = file.GetSectionContainingRva(address);
            return section;
        }

        public static string GetName(ulong address)
        {
            var symbols = GetAllSymbolsFromPdb(DLL_NAME);
            return symbols.First(x => (x.Address - x.ModBase) == address).Name;
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

        public static SymbolInfo GetSymbol(string name) {
            var symbols = GetAllSymbolsFromPdb(DLL_NAME);
            return symbols.First(x => x.Name == name);
        }

        public static uint GetSize(string name) {
            var symbol = GetSymbol(name);
            return symbol.Size;
        }

        [Flags]
        public enum SymFlag : uint
        {
            VALUEPRESENT = 0x00000001,
            REGISTER = 0x00000008,
            REGREL = 0x00000010,
            FRAMEREL = 0x00000020,
            PARAMETER = 0x00000040,
            LOCAL = 0x00000080,
            CONSTANT = 0x00000100,
            EXPORT = 0x00000200,
            FORWARDER = 0x00000400,
            FUNCTION = 0x00000800,
            VIRTUAL = 0x00001000,
            THUNK = 0x00002000,
            TLSREL = 0x00004000,
        }

        [Flags]
        public enum SymTagEnum : uint
        {
            Null,
            Exe,
            Compiland,
            CompilandDetails,
            CompilandEnv,
            Function,
            Block,
            Data,
            Annotation,
            Label,
            PublicSymbol,
            UDT,
            Enum,
            FunctionType,
            PointerType,
            ArrayType,
            BaseType,
            Typedef,
            BaseClass,
            Friend,
            FunctionArgType,
            FuncDebugStart,
            FuncDebugEnd,
            UsingNamespace,
            VTableShape,
            VTable,
            Custom,
            Thunk,
            CustomType,
            ManagedType,
            Dimension
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct SymbolInfo {
            public uint SizeOfStruct;
            public uint TypeIndex;
            public ulong Reserved1;
            public ulong Reserved2;
            public uint Reserved3;
            public uint Size;
            public ulong ModBase;
            public SymFlag Flags;
            public ulong Value;
            public ulong Address;
            public uint Register;
            public uint Scope;
            public SymTagEnum Tag;
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

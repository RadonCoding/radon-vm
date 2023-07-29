using AsmResolver.PE.File;

namespace VeProt_Native.Protections {
    internal interface IProtection {
        void Execute(Compiler compiler, uint oldSectionRVA, uint newSectionRVA, byte[] code);
    }
}

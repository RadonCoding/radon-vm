using AsmResolver.PE.File;

namespace radon_vm.Protections {
    internal interface IProtection {
        void Execute(Compiler compiler, uint oldSectionRVA, uint newSectionRVA, byte[] code);
    }
}

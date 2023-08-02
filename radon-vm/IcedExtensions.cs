using Iced.Intel;

namespace radon_vm {
    public static class IcedExtensions {
        public static bool IsIPRelative(this Instruction instr) {
            if (instr.IsIPRelativeMemoryOperand)
                return true;

            switch (instr.Code) {
                case Code.Jo_rel16:
                case Code.Jo_rel32_32:
                case Code.Jo_rel32_64:
                case Code.Jno_rel16:
                case Code.Jno_rel32_32:
                case Code.Jno_rel32_64:
                case Code.Jb_rel16:
                case Code.Jb_rel32_32:
                case Code.Jb_rel32_64:
                case Code.Jae_rel16:
                case Code.Jae_rel32_32:
                case Code.Jae_rel32_64:
                case Code.Je_rel16:
                case Code.Je_rel32_32:
                case Code.Je_rel32_64:
                case Code.Jne_rel16:
                case Code.Jne_rel32_32:
                case Code.Jne_rel32_64:
                case Code.Jbe_rel16:
                case Code.Jbe_rel32_32:
                case Code.Jbe_rel32_64:
                case Code.Ja_rel16:
                case Code.Ja_rel32_32:
                case Code.Ja_rel32_64:
                case Code.Js_rel16:
                case Code.Js_rel32_32:
                case Code.Js_rel32_64:
                case Code.Jns_rel16:
                case Code.Jns_rel32_32:
                case Code.Jns_rel32_64:
                case Code.Jp_rel16:
                case Code.Jp_rel32_32:
                case Code.Jp_rel32_64:
                case Code.Jnp_rel16:
                case Code.Jnp_rel32_32:
                case Code.Jnp_rel32_64:
                case Code.Jl_rel16:
                case Code.Jl_rel32_32:
                case Code.Jl_rel32_64:
                case Code.Jge_rel16:
                case Code.Jge_rel32_32:
                case Code.Jge_rel32_64:
                case Code.Jle_rel16:
                case Code.Jle_rel32_32:
                case Code.Jle_rel32_64:
                case Code.Jg_rel16:
                case Code.Jg_rel32_32:
                case Code.Jg_rel32_64:
                case Code.Jo_rel8_16:
                case Code.Jo_rel8_32:
                case Code.Jo_rel8_64:
                case Code.Jno_rel8_16:
                case Code.Jno_rel8_32:
                case Code.Jno_rel8_64:
                case Code.Jb_rel8_16:
                case Code.Jb_rel8_32:
                case Code.Jb_rel8_64:
                case Code.Jae_rel8_16:
                case Code.Jae_rel8_32:
                case Code.Jae_rel8_64:
                case Code.Je_rel8_16:
                case Code.Je_rel8_32:
                case Code.Je_rel8_64:
                case Code.Jne_rel8_16:
                case Code.Jne_rel8_32:
                case Code.Jne_rel8_64:
                case Code.Jbe_rel8_16:
                case Code.Jbe_rel8_32:
                case Code.Jbe_rel8_64:
                case Code.Ja_rel8_16:
                case Code.Ja_rel8_32:
                case Code.Ja_rel8_64:
                case Code.Js_rel8_16:
                case Code.Js_rel8_32:
                case Code.Js_rel8_64:
                case Code.Jns_rel8_16:
                case Code.Jns_rel8_32:
                case Code.Jns_rel8_64:
                case Code.Jp_rel8_16:
                case Code.Jp_rel8_32:
                case Code.Jp_rel8_64:
                case Code.Jnp_rel8_16:
                case Code.Jnp_rel8_32:
                case Code.Jnp_rel8_64:
                case Code.Jl_rel8_16:
                case Code.Jl_rel8_32:
                case Code.Jl_rel8_64:
                case Code.Jge_rel8_16:
                case Code.Jge_rel8_32:
                case Code.Jge_rel8_64:
                case Code.Jle_rel8_16:
                case Code.Jle_rel8_32:
                case Code.Jle_rel8_64:
                case Code.Jg_rel8_16:
                case Code.Jg_rel8_32:
                case Code.Jg_rel8_64:
                case Code.Xbegin_rel16:
                case Code.Xbegin_rel32:
                case Code.Loopne_rel8_16_CX:
                case Code.Loopne_rel8_32_CX:
                case Code.Loopne_rel8_16_ECX:
                case Code.Loopne_rel8_32_ECX:
                case Code.Loopne_rel8_64_ECX:
                case Code.Loopne_rel8_16_RCX:
                case Code.Loopne_rel8_64_RCX:
                case Code.Loope_rel8_16_CX:
                case Code.Loope_rel8_32_CX:
                case Code.Loope_rel8_16_ECX:
                case Code.Loope_rel8_32_ECX:
                case Code.Loope_rel8_64_ECX:
                case Code.Loope_rel8_16_RCX:
                case Code.Loope_rel8_64_RCX:
                case Code.Loop_rel8_16_CX:
                case Code.Loop_rel8_32_CX:
                case Code.Loop_rel8_16_ECX:
                case Code.Loop_rel8_32_ECX:
                case Code.Loop_rel8_64_ECX:
                case Code.Loop_rel8_16_RCX:
                case Code.Loop_rel8_64_RCX:
                case Code.Jcxz_rel8_16:
                case Code.Jcxz_rel8_32:
                case Code.Jecxz_rel8_16:
                case Code.Jecxz_rel8_32:
                case Code.Jecxz_rel8_64:
                case Code.Jrcxz_rel8_16:
                case Code.Jrcxz_rel8_64:
                case Code.Call_rel16:
                case Code.Call_rel32_32:
                case Code.Call_rel32_64:
                case Code.Jmp_rel16:
                case Code.Jmp_rel32_32:
                case Code.Jmp_rel32_64:
                case Code.Jmp_rel8_16:
                case Code.Jmp_rel8_32:
                case Code.Jmp_rel8_64:
                case Code.VEX_KNC_Jkzd_kr_rel8_64:
                case Code.VEX_KNC_Jknzd_kr_rel8_64:
                case Code.VEX_KNC_Jkzd_kr_rel32_64:
                case Code.VEX_KNC_Jknzd_kr_rel32_64:
                    return true;
                default:
                    return false;
            }
        }
        public static bool IsImmediate(this OpKind kind) {
            return kind switch {
                OpKind.Immediate8 => true,
                OpKind.Immediate8_2nd => true,
                OpKind.Immediate16 => true,
                OpKind.Immediate32 => true,
                OpKind.Immediate64 => true,
                OpKind.Immediate8to16 => true,
                OpKind.Immediate8to32 => true,
                OpKind.Immediate8to64 => true,
                OpKind.Immediate32to64 => true,
                _ => false
            };
        }
    }
}

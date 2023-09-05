#include <iostream>
#include <Windows.h>
#include "lazy_importer.hpp"
#include "vm.hpp"

void MathImmToMem(MathOperation operation, VMState* state, VMRegister reg0, uint8_t op0Size, uint64_t value0, uint64_t imm) {
	if (op0Size == 1) {
		if (operation == MathOperation::Add) {
			*reinterpret_cast<uint8_t*>(state->registers[reg0]) = value0 + imm;
		}
		else if (operation == MathOperation::Sub) {
			*reinterpret_cast<uint8_t*>(state->registers[reg0]) = value0 - imm;
		}
	}
	else if (op0Size == 2) {
		if (operation == MathOperation::Add) {
			*reinterpret_cast<uint16_t*>(state->registers[reg0]) = value0 + imm;
		}
		else if (operation == MathOperation::Sub) {
			*reinterpret_cast<uint16_t*>(state->registers[reg0]) = value0 - imm;
		}
	}
	else if (op0Size == 4) {
		if (operation == MathOperation::Add) {
			*reinterpret_cast<uint32_t*>(state->registers[reg0]) = value0 + imm;
		}
		else if (operation == MathOperation::Sub) {
			*reinterpret_cast<uint32_t*>(state->registers[reg0]) = value0 - imm;
		}
	}
	else if (op0Size == 8) {
		if (operation == MathOperation::Add) {
			*reinterpret_cast<uint64_t*>(state->registers[reg0]) = value0 + imm;
		}
		else if (operation == MathOperation::Sub) {
			*reinterpret_cast<uint64_t*>(state->registers[reg0]) = value0 - imm;
		}
	}
}

template<typename T> void HandleMathImm(MathOperation operation, VMState* state, uint8_t* bytecode) {
	VMOpKind op0Kind = static_cast<VMOpKind>(bytecode[3]);
	uint8_t op0Size = bytecode[4];
	VMRegister reg0 = static_cast<VMRegister>(bytecode[5]);
	VMRegisterPart part0 = static_cast<VMRegisterPart>(bytecode[6]);

	T imm = *reinterpret_cast<T*>(&bytecode[9]);

	uint64_t op0Mask = (op0Size == 8) ? ~0ULL : (1ULL << (op0Size * 8)) - 1;

	uint64_t value0 = (state->registers[reg0] >> (part0 == VMRegisterPart::Higher ? 8 : 0)) & op0Mask;

	if (op0Kind == VMOpKind::Register) {
		if (operation == MathOperation::Add) {
			state->registers[reg0] = value0 + imm;
		}
		else if (operation == MathOperation::Sub) {
			state->registers[reg0] = value0 - imm;
		}
	}
	else if (op0Kind == VMOpKind::Memory) {
		MathImmToMem(operation, state, reg0, op0Size, value0, imm);
	}
}

void HandleMath(MathOperation operation, VMState* state, uint8_t* bytecode) {
	VMOpKind op0Kind = static_cast<VMOpKind>(bytecode[3]);
	uint8_t op0Size = bytecode[4];
	VMRegister reg0 = static_cast<VMRegister>(bytecode[5]);
	VMRegisterPart part0 = static_cast<VMRegisterPart>(bytecode[6]);

	VMOpKind op1Kind = static_cast<VMOpKind>(bytecode[7]);
	uint8_t op1Size = bytecode[8];

	uint64_t op0Mask = (op0Size == 8) ? ~0ULL : (1ULL << (op0Size * 8)) - 1;
	uint64_t op1Mask = (op1Size == 8) ? ~0ULL : (1ULL << (op1Size * 8)) - 1;

	if (op1Kind == VMOpKind::Register) {
		VMRegister reg1 = static_cast<VMRegister>(bytecode[9]);
		VMRegisterPart part1 = static_cast<VMRegisterPart>(bytecode[10]);

		uint64_t value0 = (state->registers[reg0] >> (part0 == VMRegisterPart::Higher ? 8 : 0)) & op0Mask;
		uint64_t value1 = (state->registers[reg1] >> (part1 == VMRegisterPart::Higher ? 8 : 0)) & op1Mask;

		if (op0Kind == VMOpKind::Register) {
			if (operation == MathOperation::Add) {
				state->registers[reg0] = value0 + value1;
			}
			else if (operation == MathOperation::Sub) {
				state->registers[reg0] = value0 - value1;
			}
		}
		else if (op0Kind == VMOpKind::Memory) {
			if (operation == MathOperation::Add) {
				uint64_t result = value0 + value1;
				LI_FN(memcpy)(reinterpret_cast<uint64_t*>(state->registers[reg0]), &result, op0Size);
			}
			else if (operation == MathOperation::Sub) {
				uint64_t result = value0 - value1;
				LI_FN(memcpy)(reinterpret_cast<uint64_t*>(state->registers[reg0]), &result, op0Size);
			}
		}
	}
	else if (op1Kind == VMOpKind::Memory) {
		VMRegister reg1 = static_cast<VMRegister>(bytecode[9]);
		VMRegisterPart part1 = static_cast<VMRegisterPart>(bytecode[10]);

		if (part1 == VMRegisterPart::Higher) {
			op1Mask = op1Mask >> 8;
		}

		uint64_t value0 = (state->registers[reg0] >> (part0 == VMRegisterPart::Higher ? 8 : 0)) & op0Mask;

		uint64_t value1;
		LI_FN(memcpy)(&value1, reinterpret_cast<uint64_t*>(state->registers[reg1]), op1Size);

		value1 >>= (part1 == VMRegisterPart::Higher ? 8 : 0) & op0Mask;

		if (operation == MathOperation::Add) {
			state->registers[reg0] = value0 + value1;
		}
		else if (operation == MathOperation::Sub) {
			state->registers[reg0] = value0 - value1;
		}
	}
	else if (op1Kind == VMOpKind::Immediate8) {
		HandleMathImm<uint8_t>(operation, state, bytecode);
	}
	else if (op1Kind == VMOpKind::Immediate16) {
		HandleMathImm<uint16_t>(operation, state, bytecode);
	}
	else if (op1Kind == VMOpKind::Immediate8to16) {
		HandleMathImm<int16_t>(operation, state, bytecode);
	}
	else if (op1Kind == VMOpKind::Immediate32) {
		HandleMathImm<uint32_t>(operation, state, bytecode);
	}
	else if (op1Kind == VMOpKind::Immediate8to32) {
		HandleMathImm<int32_t>(operation, state, bytecode);
	}
	else if (op1Kind == VMOpKind::Immediate64) {
		HandleMathImm<uint64_t>(operation, state, bytecode);
	}
	else if (op1Kind == VMOpKind::Immediate8to64) {
		HandleMathImm<int64_t>(operation, state, bytecode);
	}
	else if (op1Kind == VMOpKind::Immediate32to64) {
		HandleMathImm<int64_t>(operation, state, bytecode);
	}
}

__declspec(naked) void LoadRegisters(uint64_t* registers) {
	__asm {
		mov rax, [rcx]
		mov rdx, [rcx + 16]
		mov rbx, [rcx + 24]
		//mov rsp, [rcx + 32]
		//mov rbp, [rcx + 40]
		mov rsi, [rcx + 48]
		mov rdi, [rcx + 56]
		mov r8, [rcx + 64]
		mov r9, [rcx + 72]
		mov r10, [rcx + 80]
		mov r11, [rcx + 88]
		mov r12, [rcx + 96]
		mov r13, [rcx + 104]
		mov r14, [rcx + 112]
		mov r15, [rcx + 120]

		mov rcx, [rcx + 8]

		ret
	}
}

__declspec(safebuffers) void LoadFlags(uint64_t flags) {
	__asm {
		push flags
		popfq
	}
}

// Move physical to virtual state
__declspec(safebuffers) VMState* VMEntry() {
	uint64_t registers[16];

	__asm {
		mov[registers], rax
		mov[registers + 8], rcx
		mov[registers + 16], rdx
		mov[registers + 24], rbx
		mov[registers + 32], rsp
		mov[registers + 40], rbp
		mov[registers + 48], rsi
		mov[registers + 56], rdi
		mov[registers + 64], r8
		mov[registers + 72], r9
		mov[registers + 80], r10
		mov[registers + 88], r11
		mov[registers + 96], r12
		mov[registers + 104], r13
		mov[registers + 112], r14
		mov[registers + 120], r15
	}

	uint64_t flags;

	__asm {
		pushfq
		pop flags
	}

	VMState* state = reinterpret_cast<VMState*>(LI_FN(malloc)(sizeof(VMState)));
	LI_FN(memset)(state, 0, sizeof(VMState));
	LI_FN(memcpy)(state->registers, registers, sizeof(state->registers));
	LI_FN(memcpy)(&state->rflags, &flags, sizeof(flags));

	return state;
}

uint8_t* Decrypt(uint8_t* bytes, uint8_t length, int key)
{
	uint8_t* decrpyted = reinterpret_cast<uint8_t*>(LI_FN(malloc)(length));

	for (int i = 0; i < length; i++)
	{
		decrpyted[i] = bytes[i] ^ key;
	}
	return decrpyted;
}

__declspec(safebuffers) void VMDispatcher(VMState* state, uint8_t* bytecode, int index) {
	uint8_t length = bytecode[index];
	uint8_t* decrypted = Decrypt(&bytecode[index + 1], length, index);

	VMMnemonic opCode = static_cast<VMMnemonic>(*reinterpret_cast<uint16_t*>(&decrypted[0]));

	if (opCode == VMMnemonic::Add) {
		HandleMath(MathOperation::Add, state, decrypted);
	}
	else if (opCode == VMMnemonic::Sub) {
		HandleMath(MathOperation::Sub, state, decrypted);
	}
	else if (opCode == VMMnemonic::Call) {
		state->call = *reinterpret_cast<uint64_t*>(&decrypted[4]);
	}
	LI_FN(free)(decrypted);
}

// Move virtual to physical state
__declspec(safebuffers) void VMExit(VMState* state) {
	LoadFlags(state->rflags);

	uint64_t registers[16];
	LI_FN(memcpy)(registers, state->registers, sizeof(registers));

	uint64_t stack = registers[VMRegister::RSP];
	uint64_t frame = registers[VMRegister::RBP];

	uintptr_t image = reinterpret_cast<uintptr_t>(LI_FN(GetModuleHandleA)(nullptr));
	uintptr_t address = image + state->call;

	LI_FN(free)(state);

	LoadRegisters(registers);

	__asm {
		push rax
		mov rax, address
		cmp rax, image
		pop rax
		jne equal
		je ignore

		equal:
			call address
	ignore:
	}
}
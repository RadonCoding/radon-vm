#include "runtime.hpp"
#include <iostream>
#include <Windows.h>
#include "lazy_importer.hpp"

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
	LI_FN(memcpy)(state->registers, registers, sizeof(state->registers) + 8);
	LI_FN(memcpy)(&state->rflags, &flags, sizeof(flags));

	return state;
}

void AddImmToMem(VMState* state, VMRegister reg0, uint8_t op0Size, uint64_t value0, uint64_t imm) {
	if (op0Size == 1) {
		*reinterpret_cast<uint8_t*>(state->registers[reg0]) = value0 + imm;
	}
	else if (op0Size == 2) {
		*reinterpret_cast<uint16_t*>(state->registers[reg0]) = value0 + imm;
	}
	else if (op0Size == 4) {
		*reinterpret_cast<uint32_t*>(state->registers[reg0]) = value0 + imm;
	}
	else if (op0Size == 8) {
		*reinterpret_cast<uint64_t*>(state->registers[reg0]) = value0 + imm;
	}
}

template<typename T>
void HandleAddImm(VMState* state, uint8_t* bytecode, int index) {
	VMOpKind op0Kind = static_cast<VMOpKind>(bytecode[index + 2]);
	uint8_t op0Size = bytecode[index + 3];
	VMRegister reg0 = static_cast<VMRegister>(bytecode[index + 4]);
	VMRegisterPart part0 = static_cast<VMRegisterPart>(bytecode[index + 5]);

	T imm = *reinterpret_cast<T*>(&bytecode[index + 8]);

	uint64_t op0Mask = (op0Size == 8) ? ~0ULL : (1ULL << (op0Size * 8)) - 1;

	uint64_t value0 = (state->registers[reg0] >> (part0 == VMRegisterPart::Higher ? 8 : 0)) & op0Mask;

	if (op0Kind == VMOpKind::Register) {
		state->registers[reg0] = value0 + imm;
	}
	else if (op0Kind == VMOpKind::Memory) {
		AddImmToMem(state, reg0, op0Size, value0, imm);
	}
}

void HandleAdd(VMState* state, uint8_t* bytecode, int index) {
	VMOpKind op0Kind = static_cast<VMOpKind>(bytecode[index + 2]);
	uint8_t op0Size = bytecode[index + 3];
	VMRegister reg0 = static_cast<VMRegister>(bytecode[index + 4]);
	VMRegisterPart part0 = static_cast<VMRegisterPart>(bytecode[index + 5]);

	VMOpKind op1Kind = static_cast<VMOpKind>(bytecode[index + 6]);
	uint8_t op1Size = bytecode[index + 7];

	uint64_t op0Mask = (op0Size == 8) ? ~0ULL : (1ULL << (op0Size * 8)) - 1;
	uint64_t op1Mask = (op1Size == 8) ? ~0ULL : (1ULL << (op1Size * 8)) - 1;

	if (op1Kind == VMOpKind::Register) {
		VMRegister reg1 = static_cast<VMRegister>(bytecode[index + 8]);
		VMRegisterPart part1 = static_cast<VMRegisterPart>(bytecode[index + 9]);

		uint64_t value0 = (state->registers[reg0] >> (part0 == VMRegisterPart::Higher ? 8 : 0)) & op0Mask;
		uint64_t value1 = (state->registers[reg1] >> (part1 == VMRegisterPart::Higher ? 8 : 0)) & op1Mask;

		if (op0Kind == VMOpKind::Register) {
			state->registers[reg0] = value0 + value1;
		}
		else if (op0Kind == VMOpKind::Memory) {
			LI_FN(memcpy)(reinterpret_cast<uint64_t*>(state->registers[reg0]), &value1, op0Size);
		}
	}
	else if (op1Kind == VMOpKind::Memory) {
		VMRegister reg1 = static_cast<VMRegister>(bytecode[index + 8]);
		VMRegisterPart part1 = static_cast<VMRegisterPart>(bytecode[index + 9]);

		if (part1 == VMRegisterPart::Higher) {
			op1Mask = op1Mask >> 8;
		}

		uint64_t value0 = (state->registers[reg0] >> (part0 == VMRegisterPart::Higher ? 8 : 0)) & op0Mask;

		uint64_t value1;
		LI_FN(memcpy)(&value1, reinterpret_cast<uint64_t*>(state->registers[reg1]), op1Size);

		value1 >>= (part1 == VMRegisterPart::Higher ? 8 : 0) & op0Mask;

		state->registers[reg0] = value0 + value1;
	}
	else if (op1Kind == VMOpKind::Immediate8) {
		HandleAddImm<uint8_t>(state, bytecode, index);
	}
	else if (op1Kind == VMOpKind::Immediate16) {
		HandleAddImm<uint16_t>(state, bytecode, index);
	}
	else if (op1Kind == VMOpKind::Immediate8to16) {
		HandleAddImm<int16_t>(state, bytecode, index);
	}
	else if (op1Kind == VMOpKind::Immediate32) {
		HandleAddImm<uint32_t>(state, bytecode, index);
	}
	else if (op1Kind == VMOpKind::Immediate8to32) {
		HandleAddImm<int32_t>(state, bytecode, index);
	}
	else if (op1Kind == VMOpKind::Immediate64) {
		HandleAddImm<uint64_t>(state, bytecode, index);
	}
	else if (op1Kind == VMOpKind::Immediate8to64) {
		HandleAddImm<int64_t>(state, bytecode, index);
	}
	else if (op1Kind == VMOpKind::Immediate32to64) {
		HandleAddImm<int64_t>(state, bytecode, index);
	}
}

__declspec(safebuffers) void VMDispatcher(VMState* state, uint8_t* bytecode, int index) {
	VMMnemonic opCode = static_cast<VMMnemonic>(bytecode[index]);
	uint8_t opCount = bytecode[index + 1];

	if (opCode == VMMnemonic::Add) {
		HandleAdd(state, bytecode, index);
	}
}

// Move virtual to physical state
__declspec(safebuffers) void VMExit(VMState* state) {
	LoadFlags(state->rflags);

	uint64_t registers[16];
	LI_FN(memcpy)(registers, state->registers, sizeof(registers));

	LI_FN(free)(state);

	LoadRegisters(registers);
}
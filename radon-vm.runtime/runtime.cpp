#include "runtime.hpp"

// Move physical to virtual state
__declspec(naked) void VMEntry() {
	__asm {
		// Allocate 392 bytes on stack
		sub rsp, 392

		// Skip stack
		add rsp, 256

		// Save physical state
		mov[rsp], rax
		mov[rsp + 8], rcx
		mov[rsp + 16], rdx
		mov[rsp + 24], rbx
		//mov[rsp + 32], rsp
		//mov[rsp + 40], rbp
		mov[rsp + 48], rsi
		mov[rsp + 56], rdi
		mov[rsp + 64], r8
		mov[rsp + 72], r9
		mov[rsp + 80], r10
		mov[rsp + 88], r11
		mov[rsp + 96], r12
		mov[rsp + 104], r13
		mov[rsp + 112], r14
		mov[rsp + 120], r15

		// Move to the flags
		add rsp, 128

		pushfq
		pop qword ptr[rsp + 128]

		// Move to end of the struct
		add rsp, 8

		// Load the start of the struct to rax
		lea rax, [rsp - 392]

		ret
	}
}

void VMDispatcher(VMState* state, uint8_t* bytecode, int index) {
	VMMnemonic opCode = static_cast<VMMnemonic>(bytecode[index]);
	uint8_t opCount = bytecode[index + 1];

	if (opCode == VMMnemonic::Add) {
		VMOpKind op0Kind = static_cast<VMOpKind>(bytecode[index + 2]);
		uint8_t op0Size = bytecode[index + 3];
		VMRegister reg0 = static_cast<VMRegister>(bytecode[index + 4]);

		VMOpKind op1Kind = static_cast<VMOpKind>(bytecode[index + 5]);
		uint8_t op1Size = bytecode[index + 6];

		uint64_t op0Mask = 0;
		uint64_t op1Mask = 0;

		int op0Bits = op0Size * 8;
		int op1Bits = op1Size * 8;

		for (int i = 0; i < op0Bits; i++) {
			op0Mask = (op0Mask << 1) | 1;
		}
		for (int i = 0; i < op1Bits; i++) {
			op1Mask = (op1Mask << 1) | 1;
		}

		if (op1Kind == VMOpKind::Register) {
			VMRegister reg1 = static_cast<VMRegister>(bytecode[index] + 7);
			state->registers[reg0] = (state->registers[reg0] & ~op0Mask) | ((state->registers[reg0] + state->registers[reg1]) & op0Mask);
		}
		else if (op1Kind == VMOpKind::Immediate8) {
			uint8_t imm8 = bytecode[index + 7];
			state->registers[reg0] = (state->registers[reg0] & ~op0Mask) | ((state->registers[reg0] + imm8) & op0Mask);
		}
		else if (op1Kind == VMOpKind::Immediate16) {
			uint16_t imm16 = *reinterpret_cast<uint16_t*>(&bytecode[index + 7]);
			state->registers[reg0] = (state->registers[reg0] & ~op0Mask) | ((state->registers[reg0] + imm16) & op0Mask);
		}
		else if (op1Kind == VMOpKind::Immediate8to16) {
			int8_t imm8 = static_cast<int8_t>(bytecode[index + 7]);
			int16_t imm16 = static_cast<int16_t>(imm8);
			state->registers[reg0] = (state->registers[reg0] & ~op0Mask) | ((state->registers[reg0] + imm16) & op0Mask);
		}
		else if (op1Kind == VMOpKind::Immediate32) {
			uint32_t imm32 = *reinterpret_cast<uint32_t*>(&bytecode[index + 7]);
			state->registers[reg0] = (state->registers[reg0] & ~op0Mask) | ((state->registers[reg0] + imm32) & op0Mask);
		}
		else if (op1Kind == VMOpKind::Immediate8to32) {
			int8_t imm8 = static_cast<int8_t>(bytecode[index + 7]);
			int32_t imm32 = static_cast<int32_t>(imm8);
			state->registers[reg0] = (state->registers[reg0] & ~op0Mask) | ((state->registers[reg0] + imm32) & op0Mask);
		}
		else if (op1Kind == VMOpKind::Immediate64) {
			uint64_t imm64 = *reinterpret_cast<uint64_t*>(&bytecode[index + 7]);
			state->registers[reg0] = (state->registers[reg0] & ~op0Mask) | ((state->registers[reg0] + imm64) & op0Mask);
		}
		else if (op1Kind == VMOpKind::Immediate8to64) {
			uint8_t imm8 = static_cast<int8_t>(bytecode[index + 7]);
			int64_t imm64 = static_cast<int64_t>(imm8);
			state->registers[reg0] = (state->registers[reg0] & ~op0Mask) | ((state->registers[reg0] + imm64) & op0Mask);
		}
		else if (op1Kind == VMOpKind::Immediate32to64) {
			int32_t imm32 = static_cast<int32_t>(bytecode[index + 7]);
			int64_t imm64 = static_cast<int64_t>(imm32);
			state->registers[reg0] = (state->registers[reg0] & ~op0Mask) | ((state->registers[reg0] + imm64) & op0Mask);
		}
	}
}

// Move virtual to physical state
__declspec(naked) void VMExit() {
	__asm {
		// Load physical state
		add rcx, 256

		mov rax, [rcx]
		//mov rcx, [rcx + 8]
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

		push [rcx + 128] // Push rflags onto stack
		popfq // Pop and load rflags

		mov rcx, [rcx + 8]

		ret
	}
}
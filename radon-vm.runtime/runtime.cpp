#include "runtime.hpp"
#include <iostream>

// Move physical to virtual state
__declspec(dllexport) __declspec(naked) void VMEntry() {
	__asm {
		// Allocate 400 bytes on stack
		sub rsp, 400

		// Save physical state
		mov[rsp + 256], rax
		mov[rsp + 256 + 8], rcx
		mov[rsp + 256 + 16], rdx
		mov[rsp + 256 + 24], rbx
		mov[rsp + 256 + 32], rsp
		mov[rsp + 256 + 40], rbp
		mov[rsp + 256 + 48], rsi
		mov[rsp + 256 + 56], rdi
		mov[rsp + 256 + 64], r8
		mov[rsp + 256 + 72], r9
		mov[rsp + 256 + 80], r10
		mov[rsp + 256 + 88], r11
		mov[rsp + 256 + 96], r12
		mov[rsp + 256 + 104], r13
		mov[rsp + 256 + 112], r14
		mov[rsp + 256 + 120], r15

		pushfq
		pop qword ptr[rsp + 256 + 128]

		// Load the start of the struct to rax
		mov rax, rsp

		add rsp, 400

		ret
	}
}

__declspec(dllexport) void VMDispatcher(VMState* tmp, uint8_t* bytecode, int index) {
	VMState state = *tmp;

	VMMnemonic opCode = static_cast<VMMnemonic>(bytecode[index]);
	uint8_t opCount = bytecode[index + 1];

	if (opCode == VMMnemonic::Add) {
		VMOpKind op0Kind = static_cast<VMOpKind>(bytecode[index + 2]);
		uint8_t op0Size = bytecode[index + 3];
		VMRegister reg0 = static_cast<VMRegister>(bytecode[index + 4]);
		VMRegisterPart part0 = static_cast<VMRegisterPart>(bytecode[index + 5]);

		VMOpKind op1Kind = static_cast<VMOpKind>(bytecode[index + 6]);
		uint8_t op1Size = bytecode[index + 7];

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
			VMRegister reg1 = static_cast<VMRegister>(bytecode[index + 8]);
			VMRegisterPart part1 = static_cast<VMRegisterPart>(bytecode[index + 9]);

			if (op0Kind == VMOpKind::Register) {
				state.registers[reg0] = (state.registers[reg0] & op0Mask) + (state.registers[reg1] & op1Mask);
			}
			else if (op0Kind == VMOpKind::Memory) {
				if (op0Size == 1) {
					*reinterpret_cast<uint8_t*>(state.registers[reg0]) += state.registers[reg1] & op1Mask;
				}
				else if (op0Size == 2) {
					*reinterpret_cast<uint16_t*>(state.registers[reg0]) += state.registers[reg1] & op1Mask;
				}
				else if (op0Size == 4) {
					*reinterpret_cast<uint32_t*>(state.registers[reg0]) += state.registers[reg1] & op1Mask;
				}
				else if (op0Size == 8) {
					*reinterpret_cast<uint64_t*>(state.registers[reg0]) += state.registers[reg1] & op1Mask;
				}
			}
		}
		else if (op1Kind == VMOpKind::Memory) {
			VMRegister reg1 = static_cast<VMRegister>(bytecode[index + 8]);
			VMRegisterPart part1 = static_cast<VMRegisterPart>(bytecode[index + 9]);

			uint64_t value;

			if (op1Size == 1) {
				value = *reinterpret_cast<uint8_t*>(state.registers[reg1]);
			}
			else if (op1Size == 2) {
				value = *reinterpret_cast<uint16_t*>(state.registers[reg1]);
			}
			else if (op1Size == 4) {
				value = *reinterpret_cast<uint32_t*>(state.registers[reg1]);
			}
			else if (op1Size == 8) {
				value = *reinterpret_cast<uint64_t*>(state.registers[reg1]);
			}
			state.registers[reg0] = (state.registers[reg0] & op0Mask) + (value & op1Mask);
		}
		else if (op1Kind == VMOpKind::Immediate8) {
			uint8_t imm8 = bytecode[index + 8];

			if (op0Kind == VMOpKind::Register) {
				state.registers[reg0] = (state.registers[reg0] & op0Mask) + imm8;
			}
			else if (op0Kind == VMOpKind::Memory) {
				if (op0Size == 1) {
					*reinterpret_cast<uint8_t*>(state.registers[reg0]) += imm8;
				}
				else if (op0Size == 2) {
					*reinterpret_cast<uint16_t*>(state.registers[reg0]) += imm8;
				}
				else if (op0Size == 4) {
					*reinterpret_cast<uint32_t*>(state.registers[reg0]) += imm8;
				}
				else if (op0Size == 8) {
					*reinterpret_cast<uint64_t*>(state.registers[reg0]) += imm8;
				}
			}
		}
		else if (op1Kind == VMOpKind::Immediate16) {
			uint16_t imm16 = *reinterpret_cast<uint16_t*>(&bytecode[index + 8]);

			if (op0Kind == VMOpKind::Register) {
				state.registers[reg0] = (state.registers[reg0] & op0Mask) + imm16;
			}
			else if (op0Kind == VMOpKind::Memory) {
				if (op0Size == 1) {
					*reinterpret_cast<uint8_t*>(state.registers[reg0]) += imm16;
				}
				else if (op0Size == 2) {
					*reinterpret_cast<uint16_t*>(state.registers[reg0]) += imm16;
				}
				else if (op0Size == 4) {
					*reinterpret_cast<uint32_t*>(state.registers[reg0]) += imm16;
				}
				else if (op0Size == 8) {
					*reinterpret_cast<uint64_t*>(state.registers[reg0]) += imm16;
				}
			}
		}
		else if (op1Kind == VMOpKind::Immediate8to16) {
			int8_t imm8 = static_cast<int8_t>(bytecode[index + 8]);
			int16_t imm16 = static_cast<int16_t>(imm8);

			if (op0Kind == VMOpKind::Register) {
				state.registers[reg0] = (state.registers[reg0] & op0Mask) + imm16;
			}
			else if (op0Kind == VMOpKind::Memory) {
				if (op0Size == 1) {
					*reinterpret_cast<uint8_t*>(state.registers[reg0]) += imm16;
				}
				else if (op0Size == 2) {
					*reinterpret_cast<uint16_t*>(state.registers[reg0]) += imm16;
				}
				else if (op0Size == 4) {
					*reinterpret_cast<uint32_t*>(state.registers[reg0]) += imm16;
				}
				else if (op0Size == 8) {
					*reinterpret_cast<uint64_t*>(state.registers[reg0]) += imm16;
				}
			}
		}
		else if (op1Kind == VMOpKind::Immediate32) {
			uint32_t imm32 = *reinterpret_cast<uint32_t*>(&bytecode[index + 8]);

			if (op0Kind == VMOpKind::Register) {
				state.registers[reg0] = (state.registers[reg0] & op0Mask) + imm32;
			}
			else if (op0Kind == VMOpKind::Memory) {
				if (op0Size == 1) {
					*reinterpret_cast<uint8_t*>(state.registers[reg0]) += imm32;
				}
				else if (op0Size == 2) {
					*reinterpret_cast<uint16_t*>(state.registers[reg0]) += imm32;
				}
				else if (op0Size == 4) {
					*reinterpret_cast<uint32_t*>(state.registers[reg0]) += imm32;
				}
				else if (op0Size == 8) {
					*reinterpret_cast<uint64_t*>(state.registers[reg0]) += imm32;
				}
			}
		}
		else if (op1Kind == VMOpKind::Immediate8to32) {
			int8_t imm8 = static_cast<int8_t>(bytecode[index + 8]);
			int32_t imm32 = static_cast<int32_t>(imm8);

			if (op0Kind == VMOpKind::Register) {
				state.registers[reg0] = (state.registers[reg0] & op0Mask) + imm32;
			}
			else if (op0Kind == VMOpKind::Memory) {
				if (op0Size == 1) {
					*reinterpret_cast<uint8_t*>(state.registers[reg0]) += imm32;
				}
				else if (op0Size == 2) {
					*reinterpret_cast<uint16_t*>(state.registers[reg0]) += imm32;
				}
				else if (op0Size == 4) {
					*reinterpret_cast<uint32_t*>(state.registers[reg0]) += imm32;
				}
				else if (op0Size == 8) {
					*reinterpret_cast<uint64_t*>(state.registers[reg0]) += imm32;
				}
			}
		}
		else if (op1Kind == VMOpKind::Immediate64) {
			uint64_t imm64 = *reinterpret_cast<uint64_t*>(&bytecode[index + 8]);

			if (op0Kind == VMOpKind::Register) {
				state.registers[reg0] = (state.registers[reg0] & op0Mask) + imm64;
			}
			else if (op0Kind == VMOpKind::Memory) {
				if (op0Size == 1) {
					*reinterpret_cast<uint8_t*>(state.registers[reg0]) += imm64;
				}
				else if (op0Size == 2) {
					*reinterpret_cast<uint16_t*>(state.registers[reg0]) += imm64;
				}
				else if (op0Size == 4) {
					*reinterpret_cast<uint32_t*>(state.registers[reg0]) += imm64;
				}
				else if (op0Size == 8) {
					*reinterpret_cast<uint64_t*>(state.registers[reg0]) += imm64;
				}
			}
		}
		else if (op1Kind == VMOpKind::Immediate8to64) {
			uint8_t imm8 = static_cast<int8_t>(bytecode[index + 8]);
			int64_t imm64 = static_cast<int64_t>(imm8);

			if (op0Kind == VMOpKind::Register) {
				state.registers[reg0] = (state.registers[reg0] & op0Mask) + imm64;
			}
			else if (op0Kind == VMOpKind::Memory) {
				if (op0Size == 1) {
					*reinterpret_cast<uint8_t*>(state.registers[reg0]) += imm64;
				}
				else if (op0Size == 2) {
					*reinterpret_cast<uint16_t*>(state.registers[reg0]) += imm64;
				}
				else if (op0Size == 4) {
					*reinterpret_cast<uint32_t*>(state.registers[reg0]) += imm64;
				}
				else if (op0Size == 8) {
					*reinterpret_cast<uint64_t*>(state.registers[reg0]) += imm64;
				}
			}
		}
		else if (op1Kind == VMOpKind::Immediate32to64) {
			int32_t imm32 = static_cast<int32_t>(bytecode[index + 8]);
			int64_t imm64 = static_cast<int64_t>(imm32);

			if (op0Kind == VMOpKind::Register) {
				state.registers[reg0] = (state.registers[reg0] & op0Mask) + imm64;
			}
			else if (op0Kind == VMOpKind::Memory) {
				if (op0Size == 1) {
					*reinterpret_cast<uint8_t*>(state.registers[reg0]) += imm64;
				}
				else if (op0Size == 2) {
					*reinterpret_cast<uint16_t*>(state.registers[reg0]) += imm64;
				}
				else if (op0Size == 4) {
					*reinterpret_cast<uint32_t*>(state.registers[reg0]) += imm64;
				}
				else if (op0Size == 8) {
					*reinterpret_cast<uint64_t*>(state.registers[reg0]) += imm64;
				}
			}
		}
	}

	__asm {
		lea rax, [state]
	}
}

// Move virtual to physical state
__declspec(dllexport) __declspec(naked) void VMExit() {
	__asm {
		// Load physical state
		mov rax, [rcx + 256]
		//mov rcx, [rcx + 256 + 8]
		mov rdx, [rcx + 256 + 16]
		mov rbx, [rcx + 256 + 24]
		//mov rsp, [rcx + 256 + 32]
		//mov rbp, [rcx + 256 + 40]
		mov rsi, [rcx + 256 + 48]
		mov rdi, [rcx + 256 + 56]
		mov r8, [rcx + 256 + 64]
		mov r9, [rcx + 256 + 72]
		mov r10, [rcx + 256 + 80]
		mov r11, [rcx + 256 + 88]
		mov r12, [rcx + 256 + 96]
		mov r13, [rcx + 256 + 104]
		mov r14, [rcx + 256 + 112]
		mov r15, [rcx + 256 + 120]

		push[rcx + 256 + 128] // Push rflags onto stack
		popfq // Pop and load rflags

		mov rcx, [rcx + 256 + 8]

		ret
	}
}
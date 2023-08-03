// ConsoleApplication1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <cassert>
#include "../radon-vm.runtime/runtime.cpp"

// add rax, imm
bool test1() {
	const uint64_t imm = 64;

	uint16_t mnemonic = static_cast<uint16_t>(VMMnemonic::Add);

	uint8_t bytecode[] = {
		static_cast<uint8_t>(mnemonic & 0xFF),
		static_cast<uint8_t>((mnemonic >> 8) & 0xFF),
		2,
		static_cast<uint8_t>(VMOpKind::Register),
		8,
		static_cast<uint8_t>(VMRegister::RAX),
		static_cast<uint8_t>(VMRegisterPart::None),

		static_cast<uint8_t>(VMOpKind::Immediate8),
		8,
		imm
	};

	__asm {
		xor rax, rax
	}

	__asm {
		call VMEntry

		mov rcx, rax

		push rcx

		lea rdx, bytecode
		mov r8d, 0
		call VMDispatcher

		pop rcx

		call VMExit
	}

	uint64_t result;

	__asm {
		mov result, rax
	}
	return result == imm;
}

// sub rax, imm
bool test2() {
	const uint64_t imm = 64;

	uint16_t mnemonic = static_cast<uint16_t>(VMMnemonic::Sub);

	uint8_t bytecode[] = {
		static_cast<uint8_t>(mnemonic & 0xFF),
		static_cast<uint8_t>((mnemonic >> 8) & 0xFF),
		2,
		static_cast<uint8_t>(VMOpKind::Register),
		8,
		static_cast<uint8_t>(VMRegister::RAX),
		static_cast<uint8_t>(VMRegisterPart::None),

		static_cast<uint8_t>(VMOpKind::Immediate8),
		8,
		imm
	};

	__asm {
		mov rax, imm
	}

	__asm {
		call VMEntry

		mov rcx, rax

		push rcx

		lea rdx, bytecode
		mov r8d, 0
		call VMDispatcher

		pop rcx

		call VMExit
	}

	uint64_t result;

	__asm {
		mov result, rax
	}
	return result == 0;
}

int main()
{
	std::cout << (test1() ? "SUCCESS" : "FAILURE") << std::endl;
	std::cout << (test2() ? "SUCCESS" : "FAILURE") << std::endl;
}
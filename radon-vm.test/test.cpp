// ConsoleApplication1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <cassert>
#include "../radon-vm.runtime/runtime.cpp"
#include <chrono>
#include <iomanip>

void Encrypt(uint8_t* bytes, uint8_t length, int key)
{
	for (int i = 0; i < length; i++)
	{
		bytes[i] = bytes[i] ^ key;
	}
}

// add rax, imm
bool test1() {
	const uint64_t imm = 64;

	uint16_t mnemonic = static_cast<uint16_t>(VMMnemonic::Add);

	uint8_t bytecode[] = {
		0,
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

	bytecode[0] = sizeof(bytecode) - 1;

	Encrypt(bytecode, sizeof(bytecode), 0);

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
		0,
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

	bytecode[0] = sizeof(bytecode) - 1;

	Encrypt(bytecode, sizeof(bytecode), 0);

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

// add r8l, imm
bool test3() {
	const uint8_t imm = 64;

	uint16_t mnemonic = static_cast<uint16_t>(VMMnemonic::Add);

	uint8_t bytecode[] = {
		0,
		static_cast<uint8_t>(mnemonic & 0xFF),
		static_cast<uint8_t>((mnemonic >> 8) & 0xFF),
		2,
		static_cast<uint8_t>(VMOpKind::Register),
		1,
		static_cast<uint8_t>(VMRegister::R8),
		static_cast<uint8_t>(VMRegisterPart::Lower),

		static_cast<uint8_t>(VMOpKind::Immediate8),
		1,
		imm
	};

	bytecode[0] = sizeof(bytecode) - 1;

	Encrypt(bytecode, sizeof(bytecode), 0);

	__asm {
		xor r8, r8
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

	uint8_t result;

	__asm {
		mov result, r8
	}
	return result == imm;
}

// add r12, imm
bool test4() {
	const uint8_t imm = 0xFF;

	uint16_t mnemonic = static_cast<uint16_t>(VMMnemonic::Add);

	uint8_t bytecode[] = {
		0,
		static_cast<uint8_t>(mnemonic & 0xFF),
		static_cast<uint8_t>((mnemonic >> 8) & 0xFF),
		2,
		static_cast<uint8_t>(VMOpKind::Register),
		8,
		static_cast<uint8_t>(VMRegister::R12),
		static_cast<uint8_t>(VMRegisterPart::None),

		static_cast<uint8_t>(VMOpKind::Immediate8),
		1,
		imm
	};

	bytecode[0] = sizeof(bytecode) - 1;

	Encrypt(bytecode, sizeof(bytecode), 0);

	__asm {
		mov r12, 0xFFFFFBFFFFFFFE3A
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
		mov result, r12
	}
	return result == 0xFFFFFBFFFFFFFF39;
}

template <
	class result_t = std::chrono::milliseconds,
	class clock_t = std::chrono::steady_clock,
	class duration_t = std::chrono::milliseconds
>
auto since(std::chrono::time_point<clock_t, duration_t> const& start)
{
	return std::chrono::duration_cast<result_t>(clock_t::now() - start);
}

// call cs:InitializeCriticalSectionAndSpinCount
bool test5() {
	uint16_t mnemonic = static_cast<uint16_t>(VMMnemonic::Call);
	uintptr_t target = reinterpret_cast<uintptr_t>(&InitializeCriticalSectionAndSpinCount) - reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));

	uint8_t bytecode[] = {
		0,
		static_cast<uint8_t>(mnemonic & 0xFF),
		static_cast<uint8_t>((mnemonic >> 8) & 0xFF),
		1,
		static_cast<uint8_t>(VMOpKind::Immediate64),
		static_cast<uint8_t>(target & 0xFF),
		static_cast<uint8_t>((target >> 8) & 0xFF),
		static_cast<uint8_t>((target >> 16) & 0xFF),
		static_cast<uint8_t>((target >> 24) & 0xFF),
		static_cast<uint8_t>((target >> 32) & 0xFF),
		static_cast<uint8_t>((target >> 40) & 0xFF),
		static_cast<uint8_t>((target >> 48) & 0xFF),
		static_cast<uint8_t>((target >> 56) & 0xFF),
	};

	bytecode[0] = sizeof(bytecode) - 1;

	Encrypt(bytecode, sizeof(bytecode), 0);

	CRITICAL_SECTION section;

	__asm {
		lea rcx, section
		mov rdx, 4000
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

	int result = 0;

	__asm {
		mov result, rax
	}
	return result != 0;
}

int main()
{
	std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();

	std::cout << (test1() ? "SUCCESS" : "FAILURE") << std::endl;
	std::cout << (test2() ? "SUCCESS" : "FAILURE") << std::endl;
	std::cout << (test3() ? "SUCCESS" : "FAILURE") << std::endl;
	std::cout << (test4() ? "SUCCESS" : "FAILURE") << std::endl;
	std::cout << (test5() ? "SUCCESS" : "FAILURE") << std::endl;

	std::cout << "Elapsed: " << since(start).count() << "ms" << std::endl;
}
// ConsoleApplication1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "../radon-vm.runtime/runtime.cpp"

// add rax, [rsi]
bool test1() {
	uint8_t bytecode[] = {
		VMMnemonic::Add,
		2,
		VMOpKind::Register,
		8,
		VMRegister::RAX,
		VMRegisterPart::None,

		VMOpKind::Memory,
		8,
		VMRegister::RSI,
		VMRegisterPart::None
	};

	uint64_t result = 0;

	uint64_t num1 = 64;
	uint64_t num2 = 64;

	__asm {
		mov rax, num1
		lea rsi, [num2]
	}

	__asm {
		call VMEntry

		mov rcx, rax

		lea rdx, bytecode
		mov r8d, 0
		call VMDispatcher

		mov rcx, rax
		call VMExit
	}

	__asm {
		mov result, rax
	}
	return result == num1 + num2;
}

// add [rax], rsi
bool test2() {
	uint8_t bytecode[] = {
		VMMnemonic::Add,
		2,
		VMOpKind::Memory,
		8,
		VMRegister::RAX,
		VMRegisterPart::None,

		VMOpKind::Register,
		8,
		VMRegister::RSI,
		VMRegisterPart::None
	};

	uint64_t result = 0;

	uint64_t num1 = 64;

	__asm {
		lea rax, result
		mov rsi, num1
	}

	__asm {
		call VMEntry

		mov rcx, rax

		lea rdx, bytecode
		mov r8d, 0
		call VMDispatcher

		mov rcx, rax
		call VMExit
	}
	return result == num1;
}

// add eax, ecx
bool test3() {
	uint8_t bytecode[] = {
		VMMnemonic::Add,
		2,
		VMOpKind::Register,
		4,
		VMRegister::RAX,
		VMRegisterPart::None,

		VMOpKind::Register,
		4,
		VMRegister::RCX,
		VMRegisterPart::None,
	};

	uint32_t result = 0;

	uint32_t num1 = 64;
	uint32_t num2 = 64;

	__asm {
		mov eax, num1
		mov rcx, num2
	}

	__asm {
		call VMEntry

		mov rcx, rax

		lea rdx, bytecode
		mov r8d, 0
		call VMDispatcher

		mov rcx, rax
		call VMExit
	}

	__asm {
		mov result, eax
	}
	return result == num1 + num2;
}

// add rax, imm8
bool test4() {
	const uint64_t num1 = 64;
	const uint8_t num2 = 64;

	uint8_t bytecode[] = {
		VMMnemonic::Add,
		2,
		VMOpKind::Register,
		8,
		VMRegister::RAX,
		VMRegisterPart::None,

		VMOpKind::Immediate8,
		1,
		num2
	};

	uint32_t result = 0;

	__asm {
		mov rax, num1
	}

	__asm {
		call VMEntry

		mov rcx, rax

		lea rdx, bytecode
		mov r8d, 0
		call VMDispatcher

		mov rcx, rax
		call VMExit
	}

	__asm {
		mov result, rax
	}
	return result == num1 + num2;
}

// add ax, imm16
bool test5() {
	const uint16_t num1 = 64;
	const uint16_t num2 = 64;

	uint8_t bytecode[] = {
		VMMnemonic::Add,
		2,
		VMOpKind::Register,
		2,
		VMRegister::RAX,
		VMRegisterPart::None,

		VMOpKind::Immediate16,
		2,
		num2 & 0xFF,
		(num2 >> 8) & 0xFF
	};

	uint16_t result = 0;

	__asm {
		mov ax, num1
	}

	__asm {
		call VMEntry

		mov rcx, rax

		lea rdx, bytecode
		mov r8d, 0
		call VMDispatcher

		mov rcx, rax
		call VMExit
	}

	__asm {
		mov result, ax
	}
	return result == num1 + num2;
}

// add eax, imm32
bool test6() {
	const uint32_t num1 = 64;
	const uint32_t num2 = 64;

	uint8_t bytecode[] = {
		VMMnemonic::Add,
		2,
		VMOpKind::Register,
		4,
		VMRegister::RAX,
		VMRegisterPart::None,

		VMOpKind::Immediate32,
		4,
		num2 & 0xFF,
		(num2 >> 8) & 0xFF,
		(num2 >> 16) & 0xFF,
		(num2 >> 24) & 0xFF
	};

	uint32_t result = 0;

	__asm {
		mov eax, num1
	}

	__asm {
		call VMEntry

		mov rcx, rax

		lea rdx, bytecode
		mov r8d, 0
		call VMDispatcher

		mov rcx, rax
		call VMExit
	}

	__asm {
		mov result, eax
	}
	return result == num1 + num2;
}

// add [rax], al
bool test7() {
	uint8_t bytecode[] = {
		VMMnemonic::Add,
		2,
		VMOpKind::Memory,
		8,
		VMRegister::RAX,
		VMRegisterPart::None,

		VMOpKind::Register,
		1,
		VMRegister::RBX,
		VMRegisterPart::Higher
	};

	uint64_t result = 0;

	uint8_t num1 = 64;

	__asm {
		lea rax, result
		mov bh, num1
	}

	__asm {
		call VMEntry

		mov rcx, rax

		lea rdx, bytecode
		mov r8d, 0
		call VMDispatcher

		mov rcx, rax
		call VMExit
	}
	return result == num1;
}

int main()
{
	std::cout << (test1() ? "SUCCESS" : "FAILURE") << std::endl;
	std::cout << (test2() ? "SUCCESS" : "FAILURE") << std::endl;
	std::cout << (test3() ? "SUCCESS" : "FAILURE") << std::endl;
	std::cout << (test4() ? "SUCCESS" : "FAILURE") << std::endl;
	std::cout << (test5() ? "SUCCESS" : "FAILURE") << std::endl;
	std::cout << (test6() ? "SUCCESS" : "FAILURE") << std::endl;
	std::cout << (test7() ? "SUCCESS" : "FAILURE") << std::endl;
}
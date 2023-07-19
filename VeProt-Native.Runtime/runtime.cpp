#include "runtime.hpp"

void __declspec(naked) VMEntry() {
	__asm {
		// Move physical to virtual state
	}
}

void __declspec(naked) VMDispatcher() {
	__asm {
		// Resolve bytecode based on caller IP
	}
}

void __declspec(naked) VMExit() {
	__asm {
		// Move virtual to physical state
	}
}
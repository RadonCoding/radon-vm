#include "runtime.h"

inline uint32_t Hash(char* pInput) {
	uint32_t hash = 5381;

	char* p = pInput;

	while (*p++) {
		char ch = *p;
		if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
		hash = ((hash << 5) + hash) + static_cast<uint8_t>(ch);
	}
	return hash;
}

inline uint32_t Hash(wchar_t* pInput) {
	uint32_t hash = 5381;

	wchar_t* p = pInput;

	while (*p++) {
		char ch = static_cast<char>(*p);
		if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
		hash = ((hash << 5) + hash) + static_cast<uint8_t>(ch);
	}
	return hash;
}

void* Resolve(uint32_t lib, uint32_t func) {
	PPEB pPeb = reinterpret_cast<PPEB>(__readgsqword(FIELD_OFFSET(TEB, ProcessEnvironmentBlock)));

	PPEB_LDR_DATA pLdr = pPeb->Ldr;
	PLIST_ENTRY pModules = &pLdr->InMemoryOrderModuleList;

	PLIST_ENTRY pCurrent = pModules->Flink;

	// Walk the LIST_ENTRY to find the DLL which has a name that matches the hash
	// Then find a function from it's exports that matches the hash
	while (pCurrent != pModules) {
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pCurrent, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		if (Hash(pEntry->BaseDllName.Buffer) == lib) {
			PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pEntry->DllBase);
			PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uint8_t*>(pDosHeader) + pDosHeader->e_lfanew);
			PIMAGE_EXPORT_DIRECTORY pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<uint8_t*>(pDosHeader) +
				pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

			uint32_t* pNames = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(pDosHeader) + pExportDir->AddressOfNames);
			uint16_t* pOrdinals = reinterpret_cast<uint16_t*>(reinterpret_cast<uint8_t*>(pDosHeader) + pExportDir->AddressOfNameOrdinals);
			uint32_t* pFunctions = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(pDosHeader) + pExportDir->AddressOfFunctions);

			for (uint32_t i = 0; i < pExportDir->NumberOfNames; i++) {
				char* pName = reinterpret_cast<char*>(reinterpret_cast<uint8_t*>(pDosHeader) + pNames[i]);

				if (Hash(pName) == func) {
					uint16_t ordinal = pOrdinals[i];
					return reinterpret_cast<void*>(reinterpret_cast<uint8_t*>(pDosHeader) + pFunctions[ordinal]);
				}
			}
			return nullptr;
		}
		pCurrent = pCurrent->Flink;
	}
	return nullptr;
}
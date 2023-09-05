#include <cstdint>
#include <vector>
#include <random>
#include <map>
#include <iostream>
#include <Windows.h>

constexpr size_t KEY_SIZE = 32;

class RuntimeInstruction {
public:
	inline void crypt() {
		for (size_t i = 0; i < this->bytes.size(); i++) {
			this->bytes[i] ^= this->key[i % this->key.size()];
		}
	}

	inline const std::vector<uint8_t>& getBytes() const {
		return this->bytes;
	}

	inline const std::vector<uint8_t>& getKey() const {
		return this->key;
	}

	RuntimeInstruction(std::vector<uint8_t> bytes) {
		this->bytes = bytes;

		std::random_device rd;
		std::mt19937_64 gen(rd());
		std::uniform_int_distribution<uint64_t> dist(0, 255);

		for (size_t i = 0; i < KEY_SIZE; i++) {
			this->key.push_back(static_cast<uint8_t>(dist(gen)));
		}
		this->crypt();
	}

	RuntimeInstruction(std::vector<uint8_t> bytes, std::vector<uint8_t> key) {
		this->bytes = bytes;
		this->key = key;
	}

	RuntimeInstruction() {}
private:
	std::vector<uint8_t> bytes;
	std::vector<uint8_t> key;
};

class Runtime {
public:
	std::vector<uint8_t> serialize() const {
		std::vector<uint8_t> serialized;

		const size_t instrCount = this->runtimeInstrs.size();
		serialized.insert(serialized.end(), reinterpret_cast<const uint8_t*>(&instrCount), reinterpret_cast<const uint8_t*>(&instrCount) + sizeof(instrCount));

		for (const auto& [rva, instr] : this->runtimeInstrs) {
			const uint32_t rvaSize = sizeof(rva);
			serialized.insert(serialized.end(), reinterpret_cast<const uint8_t*>(&rva), reinterpret_cast<const uint8_t*>(&rva) + rvaSize);

			const std::vector<uint8_t>& instrBytes = instr.getBytes();
			const size_t instrSize = instrBytes.size();
			serialized.insert(serialized.end(), reinterpret_cast<const uint8_t*>(&instrSize), reinterpret_cast<const uint8_t*>(&instrSize) + sizeof(instrSize));
			serialized.insert(serialized.end(), instrBytes.data(), instrBytes.data() + instrBytes.size());

			const std::vector<uint8_t>& keyBytes = instr.getKey();
			const size_t keySize = keyBytes.size();
			serialized.insert(serialized.end(), reinterpret_cast<const uint8_t*>(&keySize), reinterpret_cast<const uint8_t*>(&keySize) + sizeof(keySize));
			serialized.insert(serialized.end(), keyBytes.data(), keyBytes.data() + keyBytes.size());
		}
		const uint32_t oldRVASize = sizeof(this->oldRVA);
		serialized.insert(serialized.end(), reinterpret_cast<const uint8_t*>(&oldRVASize), reinterpret_cast<const uint8_t*>(&oldRVASize) + sizeof(oldRVASize));
		serialized.insert(serialized.end(), reinterpret_cast<const uint8_t*>(&this->oldRVA), reinterpret_cast<const uint8_t*>(&this->oldRVA) + oldRVASize);

		return serialized;
	}

	void deserialize(const std::vector<uint8_t>& serialized) {
		size_t offset = 0;

		size_t instrCount;
		std::memcpy(&instrCount, &serialized[offset], sizeof(instrCount));
		offset += sizeof(instrCount);

		for (uint32_t i = 0; i < instrCount; i++) {
			uintptr_t rva;
			std::memcpy(&rva, &serialized[offset], sizeof(rva));
			offset += sizeof(rva);

			size_t instrSize;
			std::memcpy(&instrSize, &serialized[offset], sizeof(instrSize));
			offset += sizeof(instrSize);
			std::vector<uint8_t> instrBytes(&serialized[offset], &serialized[offset] + instrSize);
			offset += instrSize;

			size_t keySize;
			std::memcpy(&keySize, &serialized[offset], sizeof(keySize));
			offset += sizeof(keySize);

			std::vector<uint8_t> keyBytes(&serialized[offset], &serialized[offset] + keySize);
			offset += keySize;

			RuntimeInstruction runtimeInstr(instrBytes, keyBytes);
			this->runtimeInstrs.emplace(rva, runtimeInstr);
		}

		uint32_t oldRVASize;
		std::memcpy(&oldRVASize, &serialized[offset], sizeof(oldRVASize));
		offset += sizeof(oldRVASize);
		std::memcpy(&this->oldRVA, &serialized[offset], oldRVASize);
		offset += oldRVASize;
	}

	inline void addInstruction(uintptr_t rva, RuntimeInstruction runtimeInstr) {
		this->runtimeInstrs.emplace(rva, runtimeInstr);
	}

	inline bool hasInstruction(uintptr_t rva) {
		return this->runtimeInstrs.contains(rva);
	}

	inline RuntimeInstruction& getInstruction(uintptr_t rva) {
		return this->runtimeInstrs[rva];
	}

	uintptr_t getOldRVA() {
		if (this->oldRVA != 0) {
			const uintptr_t oldRVA = this->oldRVA;
			this->oldRVA = 0;
			return oldRVA;
		}
		return 0;
	}

	inline void setOldRVA(uintptr_t rva) {
		this->oldRVA = rva;
	}

	Runtime() {}
private:
	std::map<uintptr_t, RuntimeInstruction> runtimeInstrs;
	uintptr_t oldRVA = 0;
};

class Payload {
public:
	inline void crypt() {
		for (size_t i = 0; i < this->bytes.size(); i++) {
			this->bytes[i] ^= this->key[i % this->key.size()];
		}
	}

	inline const std::vector<uint8_t> getBytes() const {
		return this->bytes;
	}

	inline const std::vector<uint8_t> getKey() const {
		return this->key;
	}

	const std::vector<uint8_t> serialize() const {
		std::vector<uint8_t> serialized;

		const size_t bytesSize = this->bytes.size();
		serialized.insert(serialized.end(), reinterpret_cast<const uint8_t*>(&bytesSize), reinterpret_cast<const uint8_t*>(&bytesSize) + sizeof(bytesSize));
		serialized.insert(serialized.end(), this->bytes.begin(), this->bytes.end());

		const size_t keySize = this->key.size();
		serialized.insert(serialized.end(), reinterpret_cast<const uint8_t*>(&keySize), reinterpret_cast<const uint8_t*>(&keySize) + sizeof(keySize));
		serialized.insert(serialized.end(), this->key.begin(), this->key.end());

		return serialized;
	}

	void deserialize(const std::vector<uint8_t> serialized) {
		size_t offset = 0;

		uint32_t bytesSize;
		std::memcpy(&bytesSize, &serialized[0], sizeof(bytesSize));
		offset += sizeof(bytesSize);
		this->bytes.insert(this->bytes.begin(), &serialized[offset], &serialized[offset] + bytesSize);
		offset += bytesSize;

		uint32_t keySize;
		std::memcpy(&keySize, &serialized[offset], sizeof(keySize));
		offset += sizeof(keySize);
		this->key.insert(this->key.begin(), &serialized[offset], &serialized[offset] + keySize);
	}

	Payload(const std::vector<uint8_t> bytes) {
		this->bytes = bytes;

		std::random_device rd;
		std::mt19937 gen(rd());

		for (size_t i = 0; i < KEY_SIZE; i++) {
			this->key.push_back(static_cast<uint8_t>(gen()));
		}
		this->crypt();
	}

	Payload() {}
private:
	std::vector<uint8_t> bytes;
	std::vector<uint8_t> key;
};
#pragma once
#include <cstdint>
#include "structs.h"

#define EXPORT extern "C" __declspec(dllexport)

/// <summary>
/// Hashes a string.
/// </summary>
/// <param name="str">The string to hash.</param>
/// <returns>The hash of the string.</returns>
EXPORT inline uint32_t Hash(char* pInput);

/// <summary>
/// Resolves a imported function address.
/// </summary>
/// <param name="lib">The library name hash.</param>
/// <param name="func">The function name hash.</param>
/// <returns>The address of the imported function.</returns>
EXPORT void* Resolve(uint32_t lib, uint32_t func);
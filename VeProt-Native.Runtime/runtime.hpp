#pragma once

#define EXPORT extern "C" __declspec(dllexport)

EXPORT void __declspec(naked) VMEntry();
EXPORT void __declspec(naked) VMDispatcher();
EXPORT void __declspec(naked) VMExit();
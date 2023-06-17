#pragma once

#define EXPORT extern "C" __declspec(dllexport)

EXPORT void VMEntry();
EXPORT void VMDispatcher();
EXPORT void VMExit();
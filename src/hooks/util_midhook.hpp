#pragma once

#include "core/standdown.hpp"
#include <Geode/Geode.hpp>
#include <string>

#if defined(_WIN32)
#include <safetyhook.hpp>
#include <unordered_map>
#endif

namespace gucci {

#if defined(_WIN32)

    static std::unordered_map<std::string, safetyhook::MidHook> g_midHooks;

    inline int g_midhookAttempts = 0;
    inline int g_midhookFailures = 0;
    inline int g_patchAttempts = 0;
    inline int g_patchFailures = 0;

    inline bool util_midhook(
        uintptr_t address,
        const std::string& name,
        safetyhook::MidHookFn fn
    ) {
        if (auto const* bot = standDownBot()) {
            geode::log::warn(
                "[GucciBot] Skipped midhook '{}': {} is enabled",
                name,
                bot->name
            );
            return false;
        }

        ++g_midhookAttempts;

        auto hook = safetyhook::create_mid(
            reinterpret_cast<void*>(address),
            fn
        );

        if (!hook) {
            ++g_midhookFailures;
            geode::log::error(
                "[GucciBot] Failed to install midhook '{}'",
                name
            );
            return false;
        }

        g_midHooks.emplace(name, std::move(hook));
        geode::log::info(
            "[GucciBot] Installed midhook '{}'",
            name
        );
        return true;
    }

#else

    // SafetyHook is Windows/x86-64 only.
    // Android ARM64 skips GucciBot's Windows midhooks.
    inline int g_midhookAttempts = 0;
    inline int g_midhookFailures = 0;
    inline int g_patchAttempts = 0;
    inline int g_patchFailures = 0;

#endif

} // namespace gucci

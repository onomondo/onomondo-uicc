/*
 * Copyright (c) 2024 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

/*
 * This file solely exist to print config opitons at compile time
 */
#pragma once

#ifdef CONFIG_USE_SYSTEM_HEAP
#pragma message "Using CONFIG_USE_SYSTEM_HEAP"
#else
#pragma message "Using port_malloc and port_free instead of system default"
#endif // CONFIG_USE_SYSTEM_HEAP

#ifdef CONFIG_USE_EXPERIMENTAL_SUSPEND_COMMAND
#pragma message "Building with experimental support for suspend"
#endif // CONFIG_USE_EXPERIMENTAL_SUSPEND_COMMAND

#if defined(CONFIG_EXTERNAL_KEY_LOAD) && defined(CONFIG_EXTERNAL_CRYPTO_IMPL)
#error "External CONFIG_EXTERNAL_CRYPTO_IMPL implementation and CONFIG_EXTERNAL_KEY_LOAD should not be enabled at the same time."
#endif // CONFIG_EXTERNAL_KEY_LOAD && EXTERNAL_CRYPTO_IMPLEMENTATION

#ifdef CONFIG_EXTERNAL_KEY_LOAD
#pragma message "Enabling CONFIG_EXTERNAL_KEY_LOAD"
#endif // CONFIG_EXTERNAL_KEY_LOAD

#ifdef CONFIG_EXTERNAL_CRYPTO_IMPL
#pragma message "Enabling CONFIG_EXTERNAL_CRYPTO_IMPL"
#endif // CONFIG_EXTERNAL_CRYPTO_IMPL


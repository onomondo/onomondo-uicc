#ifndef INCLUDE_ONOMONDO_SOFTSIM_CONFIG_H_
#define INCLUDE_ONOMONDO_SOFTSIM_CONFIG_H_

#ifdef CONFIG_USE_SYSTEM_HEAP
  #pragma message "Using CONFIG_USE_SYSTEM_HEAP"
#else  // DEFAULT
  #pragma message "Using port_malloc and port_free instead of system default"
#endif	// CONFIG_USE_SYSTEM_HEAP

#ifdef CONFIG_USE_EXPERIMENTAL_SUSPEND_COMMAND
  #pragma message "Building with experimental support for suspend"
#endif // CONFIG_USE_EXPERIMENTAL_SUSPEND_COMMAND
#endif // INCLUDE_ONOMONDO_SOFTSIM_CONFIG_H_


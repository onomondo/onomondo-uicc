#ifndef INCLUDE_ONOMONDO_SOFTSIM_CONFIG_H_
#define INCLUDE_ONOMONDO_SOFTSIM_CONFIG_H_

#ifdef CONFIG_USE_SYSTEM_HEAP
  #pragma message "Using CONFIG_USE_SYSTEM_HEAP"
#else  // DEFAULT
  #pragma message "Using port_malloc and port_free instead of system default"
#endif	// CONFIG_USE_SYSTEM_HEAP

#endif // INCLUDE_ONOMONDO_SOFTSIM_CONFIG_H_


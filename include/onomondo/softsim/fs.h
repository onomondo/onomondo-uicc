#ifndef FS_SS_H
#define FS_SS_H

#include <stddef.h>
#include <stdint.h>

typedef void *ss_FILE;

ss_FILE ss_fopen(char *path, char *mode) __attribute__((weak));
int ss_fclose(ss_FILE) __attribute__((weak));
size_t ss_fread(void *ptr, size_t size, size_t nmemb, ss_FILE fp) __attribute__((weak));
size_t ss_fwrite(const void *prt, size_t size, size_t count, ss_FILE f) __attribute__((weak));
int ss_file_size(char *path) __attribute__((weak));
int ss_delete_file(const char *path) __attribute__((weak));
int ss_delete_dir(const char *path) __attribute__((weak));
int ss_fseek(ss_FILE fp, long offset, int whence) __attribute__((weak));
int ss_access(const char *path, int amode) __attribute__((weak));
int ss_create_dir(const char *path, uint32_t mode) __attribute__((weak));
#endif /* FS_SS_H */

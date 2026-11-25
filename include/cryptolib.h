#ifndef CRYPTOLIB_H
#define CRYPTOLIB_H

/* Shared status values for APIs returning int. Pointer-returning compatibility
 * functions still signal failure with NULL; void hash primitives require valid
 * initialized contexts and buffers. AES_* names remain aliases for compatibility. */
#define CRYPTOLIB_SUCCESS 0
#define CRYPTOLIB_ERROR_INVALID_PARAM -1
#define CRYPTOLIB_ERROR_FILE_OPEN -2
#define CRYPTOLIB_ERROR_FILE_READ -3
#define CRYPTOLIB_ERROR_FILE_WRITE -4
#define CRYPTOLIB_ERROR_MEMORY -5
#define CRYPTOLIB_ERROR_RANDOM -6
#define CRYPTOLIB_ERROR_BUFFER_TOO_SMALL -7

#endif

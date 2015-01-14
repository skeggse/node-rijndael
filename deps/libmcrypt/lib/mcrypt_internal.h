#ifndef LIBDEFS_H
#define LIBDEFS_H
#include <libdefs.h>
#endif

/* Local Defines */

#ifndef lt_ptr
/* older version of libltdl */
# define lt_ptr lt_ptr_t
#endif

typedef struct {
	char* name;
	lt_ptr address;
} mcrypt_preloaded;

typedef struct {
		char name[64];
} mcrypt_fhandle;

#define MCRYPT_INTERNAL_HANDLER (void*)-1

struct CRYPT_STREAM {
	mcrypt_fhandle algorithm_handle;
	mcrypt_fhandle mode_handle;

	// holds the algorithm's internal key
	byte *akey;

	// holds the mode's internal buffers
	byte *abuf;

	// holds the key
	byte *keyword_given;

	// these were included to speed up encryption/decryption process, to remove
	// the need to resolve symbols every time
	lt_ptr m_encrypt;
	lt_ptr m_decrypt;
	lt_ptr a_encrypt;
	lt_ptr a_decrypt;
	lt_ptr a_block_size;
};

typedef struct CRYPT_STREAM CRYPT_STREAM;
typedef struct CRYPT_STREAM* MCRYPT;

#define MCRYPT_FAILED 0x0

int mcrypt_module_close(MCRYPT td);

// frontends

int end_mcrypt(MCRYPT td, void *buf);
int mcrypt_enc_get_size(MCRYPT td);
int mcrypt_mode_get_size(MCRYPT td);
int mcrypt_set_key(MCRYPT td, void *a, const void*, int c, const void*, int e);
int mcrypt_enc_get_block_size(MCRYPT td);
int __mcrypt_get_block_size(MCRYPT td);
int mcrypt_enc_get_algo_iv_size(MCRYPT td);
int mcrypt_enc_get_iv_size(MCRYPT td);
int mcrypt_enc_get_key_size(MCRYPT td);
int *mcrypt_enc_get_supported_key_sizes(MCRYPT td, int* out_size);
int mcrypt_enc_is_block_algorithm(MCRYPT td);
char *mcrypt_enc_get_algorithms_name(MCRYPT td);
int init_mcrypt(MCRYPT td, void *buf, const void*, int, const void*);
int mcrypt(MCRYPT td, void *buf, void *a, int b);
int mdecrypt(MCRYPT td, void *buf, void *a, int b);
char *mcrypt_enc_get_modes_name(MCRYPT td);
int mcrypt_enc_is_block_mode(MCRYPT td);
int mcrypt_enc_mode_has_iv(MCRYPT td);
int mcrypt_enc_is_block_algorithm_mode(MCRYPT td);
int mcrypt_module_algorithm_version(const char *algorithm);
int mcrypt_module_mode_version(const char *mode);
int mcrypt_get_algo_iv_size(MCRYPT td);
int mcrypt_get_size(MCRYPT td);


#define MCRYPT_UNKNOWN_ERROR -1
#define MCRYPT_ALGORITHM_MODE_INCOMPATIBILITY -2
#define MCRYPT_KEY_LEN_ERROR -3
#define MCRYPT_MEMORY_ALLOCATION_ERROR -4
#define MCRYPT_UNKNOWN_MODE -5
#define MCRYPT_UNKNOWN_ALGORITHM -6

lt_ptr mcrypt_sym(mcrypt_fhandle, char* str);
lt_ptr _mcrypt_search_symlist_lib(const char* name);
lt_ptr _mcrypt_search_symlist_sym(mcrypt_fhandle handle, const char* _name);

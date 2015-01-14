/*
 * Copyright (C) 1998,1999,2000,2001 Nikos Mavroyanopoulos
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef LIBDEFS_H
#define LIBDEFS_H
#include <libdefs.h>
#endif

#include <bzero.h>
#include <mcrypt_internal.h>
#include <xmemory.h>

extern const mcrypt_preloaded mps[];

#define MAX_MOD_SIZE 1024

static inline char *strdup(const char *string)
{
	size_t len = strlen(string);
	char *copy = malloc(len);
	memcpy(copy, string, len);
	return copy;
}

static int mcrypt_strcmp(const char *str1, const char *str2) {
	int i, len;

	if (strlen(str1) != strlen(str2)) return -1;

	len = strlen(str1);

	for (i = 0; i < len; i++) {
		if (str1[i] == '_' && str2[i] == '-') continue;
		if (str2[i] == '_' && str1[i] == '-') continue;
		if (str1[i] != str2[i]) return -1;
	}

	return 0;
}

lt_ptr _mcrypt_search_symlist_lib(const char *name) {
	int i = 0;

	while (mps[i].name != 0 || mps[i].address != 0) {
		if (mps[i].name != NULL && mps[i].address == NULL) {
			if (mcrypt_strcmp(name, mps[i].name) == 0) {
				 return (void*) -1;
			}
		}
		i++;
	}

	return NULL;
}

lt_ptr _mcrypt_search_symlist_sym(mcrypt_fhandle handle, const char *_name)
{
	int i = 0;
	char name[MAX_MOD_SIZE];

	strcpy(name, handle.name);

	strcat(name, "_LTX_");
	strcat(name, _name);

	while (mps[i].name != 0 || mps[i].address != 0) {
		if (mps[i].name != NULL) {
			if (mcrypt_strcmp(name, mps[i].name) == 0) {
				 return mps[i].address;
			}
		}
		i++;
	}

	return NULL;
}

lt_ptr mcrypt_sym(mcrypt_fhandle handle, char *str)
{
	return _mcrypt_search_symlist_sym(handle, str);
}

WIN32DLL_DEFINE
int mcrypt_module_close(MCRYPT td)
{
	if (td == NULL) {
		return MCRYPT_UNKNOWN_ERROR;
	}

	free(td);

	return 0;
}

WIN32DLL_DEFINE
void *mcrypt_fopen(mcrypt_fhandle *handle, const char *filename)
{
	if (!filename || !*filename) {
		return MCRYPT_FAILED;
	}

	if (strlen(filename) >= sizeof(handle->name) ||
			_mcrypt_search_symlist_lib(filename) == NULL) {
		return MCRYPT_FAILED;
	}

	strcpy(handle->name, filename);

	return MCRYPT_INTERNAL_HANDLER;
}

WIN32DLL_DEFINE
MCRYPT mcrypt_module_open(const char *algorithm, const char *mode)
{
	MCRYPT td;
	void *ret;

	td = calloc(1, sizeof(CRYPT_STREAM));
	if (td == NULL) {
		return MCRYPT_FAILED;
	}

	ret = mcrypt_fopen(&td->algorithm_handle, algorithm);
	if (ret == NULL) {
		free(td);
		return MCRYPT_FAILED;
	}

	ret = mcrypt_fopen(&td->mode_handle, mode);
	if (ret == NULL) {
		free(td);
		return MCRYPT_FAILED;
	}

	td->a_encrypt = mcrypt_sym(td->algorithm_handle, "_mcrypt_encrypt");
	td->a_decrypt = mcrypt_sym(td->algorithm_handle, "_mcrypt_decrypt");
	td->m_encrypt = mcrypt_sym(td->mode_handle, "_mcrypt");
	td->m_decrypt = mcrypt_sym(td->mode_handle, "_mdecrypt");
	td->a_block_size = mcrypt_sym(td->algorithm_handle, "_mcrypt_get_block_size");

	if (td->a_encrypt == NULL || td->a_decrypt == NULL || td->m_encrypt == NULL ||
	    td->m_decrypt == NULL || td->a_block_size == NULL) {
		free(td);
		return MCRYPT_FAILED;
	}

	if (mcrypt_enc_is_block_algorithm_mode(td) !=
	    mcrypt_enc_is_block_algorithm(td)) {
		// mcrypt_module_close(td);
		free(td);
		return MCRYPT_FAILED;
	}

	return td;
}



/* Modules' frontends */

WIN32DLL_DEFINE
int mcrypt_enc_get_state(MCRYPT td, void *iv, int *size)
{
	int (*__mcrypt_get_state)(void*, void*, int*);

	__mcrypt_get_state = mcrypt_sym(td->mode_handle, "_mcrypt_get_state");
	if (__mcrypt_get_state==NULL) {
		return MCRYPT_UNKNOWN_ERROR;
	}
	return __mcrypt_get_state(td->abuf, iv, size);
}

WIN32DLL_DEFINE
int mcrypt_set_key(MCRYPT td, void *a, const void *key, int keysize, const void *iv, int e)
{
	int (*__mcrypt_set_key_stream)(void*, const void*, int, const void*, int);
	int (*__mcrypt_set_key_block)(void*, const void*, int);

	if (mcrypt_enc_is_block_algorithm(td) == 0) {
		/* stream */
		__mcrypt_set_key_stream = mcrypt_sym(td->algorithm_handle, "_mcrypt_set_key");
		if (__mcrypt_set_key_stream == NULL) {
			return -2;
		}

		return __mcrypt_set_key_stream(a, key, keysize, iv, e);
	} else {
		__mcrypt_set_key_block = mcrypt_sym(td->algorithm_handle, "_mcrypt_set_key");
		if (__mcrypt_set_key_block == NULL) {
			return -2;
		}

		return __mcrypt_set_key_block(a, key, keysize);
	}
}

WIN32DLL_DEFINE
int init_mcrypt(MCRYPT td, void *buf, const void *key, int keysize, const void *iv)
{
	int (*_init_mcrypt)(void*, const void*, int, const void*, int);

	_init_mcrypt = mcrypt_sym(td->mode_handle, "_init_mcrypt");
	if (_init_mcrypt == NULL) {
		return MCRYPT_UNKNOWN_ERROR;
	}

	return _init_mcrypt(buf, key, keysize, iv, mcrypt_enc_get_block_size(td));
}

WIN32DLL_DEFINE
int end_mcrypt(MCRYPT td, void *buf)
{
	int (*_end_mcrypt)(void*);

	_end_mcrypt = mcrypt_sym(td->mode_handle, "_end_mcrypt");
	if (_end_mcrypt == NULL) {
		return MCRYPT_UNKNOWN_ERROR;
	}

	return _end_mcrypt(buf);
}

WIN32DLL_DEFINE
int mcrypt(MCRYPT td, void *buf, void *a, int b)
{
	int (*_mcrypt)(void*, void*, int, int, void*, void*, void*);

	_mcrypt = td->m_encrypt;

	return _mcrypt(buf, a, b, mcrypt_enc_get_block_size(td), td->akey,
		  td->a_encrypt, td->a_decrypt);
}

WIN32DLL_DEFINE
int mdecrypt(MCRYPT td, void *buf, void *a, int b)
{
	int (*_mdecrypt)(void*, void*, int, int, void*, void*, void*);

	_mdecrypt = td->m_decrypt;

	return _mdecrypt(buf, a, b, mcrypt_enc_get_block_size(td), td->akey,
	    td->a_encrypt, td->a_decrypt);
}

WIN32DLL_DEFINE
int mcrypt_enc_get_block_size(MCRYPT td)
{
	int (*_mcrypt_get_block_size)(void) = td->a_block_size;

	return _mcrypt_get_block_size();
}

WIN32DLL_DEFINE
int mcrypt_enc_get_iv_size(MCRYPT td)
{
	return mcrypt_enc_is_block_algorithm_mode(td) == 1
		? mcrypt_enc_get_block_size(td)
		: mcrypt_get_algo_iv_size(td);
}

WIN32DLL_DEFINE
char *mcrypt_enc_get_modes_name(MCRYPT td)
{
	const char *(*_mcrypt_get_modes_name)(void);

	_mcrypt_get_modes_name = mcrypt_sym(td->mode_handle, "_mcrypt_get_modes_name");
	if (_mcrypt_get_modes_name == NULL) {
		return NULL;
	}

	return strdup(_mcrypt_get_modes_name());
}

WIN32DLL_DEFINE
int *mcrypt_enc_get_supported_key_sizes(MCRYPT td, int *len)
{
	int *(*_mcrypt_get_key_sizes)(int*);
	int *size, *ret;

	_mcrypt_get_key_sizes =
	    mcrypt_sym(td->algorithm_handle, "_mcrypt_get_supported_key_sizes");
	if (_mcrypt_get_key_sizes == NULL) {
		*len = 0;
		return NULL;
	}

	size = _mcrypt_get_key_sizes(len);

	ret = NULL;
	if (size != NULL && (*len) != 0) {
		ret = malloc(sizeof(int) * (*len));
		if (ret == NULL) return NULL;
		memcpy(ret, size, sizeof(int) * (*len));
	}

	return ret;
}

WIN32DLL_DEFINE
int mcrypt_enc_set_state(MCRYPT td, const void *iv, int size)
{
	int (*__mcrypt_set_state)(void*, const void*, int);

	__mcrypt_set_state = mcrypt_sym(td->mode_handle, "_mcrypt_set_state");
	if (__mcrypt_set_state == NULL) {
		return MCRYPT_UNKNOWN_ERROR;
	}

	return __mcrypt_set_state(td->abuf, iv, size);
}

WIN32DLL_DEFINE
char *mcrypt_enc_get_algorithms_name(MCRYPT td)
{
	const char *(*_mcrypt_get_algorithms_name)(void);

	_mcrypt_get_algorithms_name =
	    mcrypt_sym(td->algorithm_handle, "_mcrypt_get_algorithms_name");
	if (_mcrypt_get_algorithms_name == NULL) {
		return NULL;
	}

	return strdup(_mcrypt_get_algorithms_name());
}

#define mcrypt_define_getter(name, type, sym) \
WIN32DLL_DEFINE \
int mcrypt_##name(MCRYPT td) \
{ \
	int (*getter)(void); \
\
	getter = mcrypt_sym(td->type##_handle, sym); \
	if (getter == NULL) { \
		return MCRYPT_UNKNOWN_ERROR; \
	} \
\
	return getter(); \
}

mcrypt_define_getter(enc_get_key_size, algorithm, "_mcrypt_get_key_size")
mcrypt_define_getter(enc_is_block_algorithm, algorithm, "_is_block_algorithm")
mcrypt_define_getter(enc_is_block_algorithm_mode, mode, "_is_block_algorithm_mode")
mcrypt_define_getter(enc_is_block_mode, mode, "_is_block_mode")
mcrypt_define_getter(enc_mode_has_iv, mode, "_has_iv")
mcrypt_define_getter(enc_self_test, algorithm, "_mcrypt_self_test")
mcrypt_define_getter(get_algo_iv_size, algorithm, "_mcrypt_get_algo_iv_size")
mcrypt_define_getter(get_size, algorithm, "_mcrypt_get_size")
mcrypt_define_getter(mode_get_size, mode, "_mcrypt_mode_get_size")

#undef mcrypt_define_getter

#define mcrypt_module_define_getter(name, sym) \
WIN32DLL_DEFINE \
int mcrypt_module_##name(const char *module_file) { \
	mcrypt_fhandle _handle; \
	int (*getter)(void); \
	void *rr; \
\
	rr = mcrypt_fopen(&_handle, module_file); \
	if (!rr) { \
		return MCRYPT_UNKNOWN_ERROR; \
	} \
\
	getter = mcrypt_sym(_handle, sym); \
	if (getter == NULL) { \
		return MCRYPT_UNKNOWN_ERROR; \
	} \
\
	return getter(); \
}

mcrypt_module_define_getter(algorithm_version, "_mcrypt_algorithm_version")
mcrypt_module_define_getter(get_algo_block_size, "_mcrypt_get_block_size")
mcrypt_module_define_getter(get_algo_key_size, "_mcrypt_get_key_size")
mcrypt_module_define_getter(is_block_algorithm, "_is_block_algorithm")
mcrypt_module_define_getter(is_block_algorithm_mode, "_is_block_algorithm_mode")
mcrypt_module_define_getter(is_block_mode, "_is_block_mode")
mcrypt_module_define_getter(mode_version, "_mode_version")
mcrypt_module_define_getter(self_test, "_mcrypt_self_test")

#undef mcrypt_module_define_getter

WIN32DLL_DEFINE
int *mcrypt_module_get_algo_supported_key_sizes(const char *algorithm, int *len)
{
	mcrypt_fhandle _handle;
	int *(*_mcrypt_get_key_sizes)(int*);
	int *size, *ret_size;
	void *rr;

	rr = mcrypt_fopen(&_handle, algorithm);
	if (!rr) {
		*len = 0;
		return NULL;
	}

	_mcrypt_get_key_sizes =
	    mcrypt_sym(_handle, "_mcrypt_get_supported_key_sizes");
	if (_mcrypt_get_key_sizes == NULL) {
		*len = 0;
		return NULL;
	}

	ret_size = NULL;
	size = _mcrypt_get_key_sizes(len);
	if (*len == 0 || size == NULL) {
		*len = 0;
	} else {
		ret_size = malloc((*len) * sizeof(int));
		if (ret_size != NULL) {
			memcpy(ret_size, size, (*len) * sizeof(int));
		}
	}

	return ret_size;
}

/**
 * Returns false(0) if the library has not been compiled with dynamic module
 * support.
 */
int mcrypt_module_support_dynamic(void) {
	return 0;
}

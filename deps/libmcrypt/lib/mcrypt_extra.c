/*
 * Copyright (C) 1998,1999,2001 Nikos Mavroyanopoulos
 *
 * This library is free software; you can redistribute it and/or modify it under the terms of the
 * GNU Library General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any
 * later version.
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

/* $Id: mcrypt_extra.c,v 1.26 2002/12/17 10:53:34 nmav Exp $ */

#include <libdefs.h>
#include <bzero.h>
#include <xmemory.h>
#include <mcrypt_internal.h>

int mcrypt_algorithm_module_ok(const char *algorithm);
int mcrypt_mode_module_ok(const char *mode);

void *mcrypt_fopen(mcrypt_fhandle *handle, const char *filename);

extern const mcrypt_preloaded mps[];

static inline char *strdup(const char *string)
{
	size_t len = strlen(string);
	char *copy = malloc(len);
	memcpy(copy, string, len);
	return copy;
}

WIN32DLL_DEFINE
void mcrypt_free_p(char **p, int size)
{
	int i;
	for (i = 0; i < size; i++) {
		free(p[i]);
	}
	free(p);
}

WIN32DLL_DEFINE
char **mcrypt_list_algorithms(int *size)
{
	char **filename = NULL;
	int i = 0;

	*size = 0;

	while (mps[i].name != 0 || mps[i].address != 0) {
		if (mps[i].name != NULL && mps[i].address == NULL) {
			if (mcrypt_algorithm_module_ok(mps[i].name) > 0) {
				// TODO: optimize realloc, or malloc with the size of the statically
				// defined mps
				char **tmp = realloc(filename, ((*size) + 1) * sizeof(char*));
				if (tmp == NULL) {
					goto freeall;
				}
				filename = tmp;
				filename[*size] = strdup(mps[i].name);
				if (filename[*size] == NULL) {
					goto freeall;
				}
				++*size;
			}
		}
		i++;
	}

	return filename;

freeall:
	mcrypt_free_p(filename, *size);
	return NULL;
}

WIN32DLL_DEFINE
char **mcrypt_list_modes(int *size)
{
	char **filename = NULL;
	int i = 0;

	*size = 0;

	while (mps[i].name != 0 || mps[i].address != 0) {
		if (mps[i].name != NULL && mps[i].address == NULL) {
			if (mcrypt_mode_module_ok(mps[i].name) > 0) {
				char **tmp = realloc(filename, ((*size) + 1) * sizeof(char*));
				if (tmp == NULL) {
					goto freeall;
				}
				filename = tmp;
				filename[*size] = strdup(mps[i].name);
				if (filename[*size] == NULL) {
					goto freeall;
				}
				++*size;
			}
		}
		i++;
	}

	return filename;

freeall:
	mcrypt_free_p(filename, *size);
	return NULL;
}

WIN32DLL_DEFINE
int mcrypt_algorithm_module_ok(const char *algorithm)
{
	mcrypt_fhandle _handle;
	int (*_version)(void);
	void *rr;

	if (algorithm == NULL) {
		return MCRYPT_UNKNOWN_ERROR;
	}

	rr = mcrypt_fopen(&_handle, algorithm);

	if (!rr) {
		return MCRYPT_UNKNOWN_ERROR;
	}

	_version = mcrypt_sym(_handle, "_mcrypt_algorithm_version");

	if (_version == NULL) {
		return MCRYPT_UNKNOWN_ERROR;
	}

	return _version();
}

WIN32DLL_DEFINE
int mcrypt_mode_module_ok(const char *mode)
{
	mcrypt_fhandle _handle;
	int (*_version)(void);
	void *rr;

	if (mode == NULL) {
		return MCRYPT_UNKNOWN_ERROR;
	}

	rr = mcrypt_fopen(&_handle, mode);
	if (!rr) {
		return MCRYPT_UNKNOWN_ERROR;
	}

	_version = mcrypt_sym(_handle, "_mcrypt_mode_version");

	if (_version == NULL) {
		return MCRYPT_UNKNOWN_ERROR;
	}

	return _version();
}


/* Taken from libgcrypt */

static const char *parse_version_number(const char *s, int *number)
{
	int val = 0;

	if (*s == '0' && isdigit(s[1]))
		return NULL;	/* leading zeros are not allowed */
	for (; isdigit(*s); s++) {
		val = val * 10 + ((*s) - '0');
	}
	*number = val;
	return val < 0 ? NULL : s;
}

static const char *parse_version_string(const char *s, int *major, int *minor,
    int *patch)
{
	s = parse_version_number(s, major);
	if (!s || *s != '.')
		return NULL;
	s++;
	s = parse_version_number(s, minor);
	if (!s || *s != '.')
		return NULL;
	s++;
	s = parse_version_number(s, patch);
	// patchlevel
	return s ? s : NULL;
}

/**
 * Check that the the version of the library is at minimum the requested one
 * and return the version string; return NULL if the condition is not satisfied.
 * If a NULL is passed to this function, no check is done, but the version
 * string is simply returned.
 */
const char *mcrypt_check_version(const char *req_version)
{
	const char *ver = VERSION;
	int my_major, my_minor, my_patch;
	int rq_major, rq_minor, rq_patch;
	const char *my_plvl, *rq_plvl;

	if (!req_version) {
		return ver;
	}

	my_plvl = parse_version_string(ver, &my_major, &my_minor, &my_patch);
	if (!my_plvl) {
		return NULL; /* very strange our own version is bogus */
	}
	rq_plvl = parse_version_string(req_version, &rq_major, &rq_minor, &rq_patch);
	if (!rq_plvl) {
		return NULL; /* req version string is invalid */
	}
	if (my_major > rq_major
		  || (my_major == rq_major && my_minor > rq_minor)
		  || (my_major == rq_major && my_minor == rq_minor && my_patch > rq_patch)
		  || (my_major == rq_major && my_minor == rq_minor &&
		      my_patch == rq_patch && strcmp(my_plvl, rq_plvl) >= 0)) {
		return ver;
	}
	return NULL;
}

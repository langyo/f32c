/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2009 David Schultz <das@FreeBSD.org>
 * Copyright (c) 2021 Dell EMC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#define	LINECAPP_INCR 128


ssize_t
getdelim(char ** __restrict linep, size_t * __restrict linecapp, int delim,
    FILE * __restrict fp)
{
	ssize_t linelen;

	if (linep == NULL || linecapp == NULL) {
		errno = EINVAL;
		goto error;
	}

	if (*linep == NULL) {
		*linecapp = LINECAPP_INCR;
		*linep = malloc(*linecapp);
		if (*linep == NULL) {
			errno = ENOMEM;
			goto error;
		}
	}

	for (linelen = 0;;) {
		if (read(fp->_fd, *linep + linelen, 1) != 1)
			goto error;
		if (*(*linep + linelen) == delim)
			return (linelen);
		linelen++;
		if (linelen == *linecapp) {
			*linecapp += LINECAPP_INCR;
			*linep = realloc(*linep, *linecapp);
			if (*linep == NULL) {
				errno = ENOMEM;
				goto error;
			}
		}
	}
error:
	return (-1);
}

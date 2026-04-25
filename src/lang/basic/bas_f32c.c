/*-
 * Copyright (c) 2013, 2016 Marko Zec
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

#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include <dev/io.h>

#include "bas.h"


int
bauds(void)
{
	int bauds;

	bauds = evalint();
	check();
	if (sio_setbaud(bauds))
		error(33);	/* argument error */
	normret;
}


int
bas_sleep(void)
{
	int c = 0;
	int t, target;

	RDTSC(target);

	evalreal();
	check();
	if (res.f < ZERO)
		error(33);	/* argument error */

	target += (int) (res.f * 1000.0 * freq_khz);

	do {
		__asm("di");
		RDTSC(t);
		if (t < tsc_lo)
			tsc_hi++;
		tsc_lo = t;
		__asm("ei");

		if(t - target > 0)
			break;

		c = sio_getchar(0);
#ifdef __mips__
//		asm("wait"); /* Low-power mode */
#endif
	} while (c != 3);

	if (c == 3)
		trapped = 1;
	normret;
}


int
bas_exec(void)
{
	char path[256];
	STR st;

	st = stringeval();
	NULL_TERMINATE(st);
	strcpy(path, st->strval);
	FREE_STR(st);
	check();

	execve(path, NULL, NULL);

	/* Actually, not reached */
	normret;
}

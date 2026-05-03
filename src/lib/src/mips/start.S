/*-
 * Copyright (c) 2013 - 2026 Marko Zec
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

#include <mips/asm.h>
#include <mips/regdef.h>
#include <mips/cpuregs.h>
#include <dev/io.h>


/*
 * Set small data index register, set curthread, clear BSS, and jump
 * into main().
 *
 * Assumes that the loader has already properly:
 * 1) set stack pointer
 * 2) set return address
 * 3) invalidated caches
 */

	.section .data
	.globl environ
	.type environ,@object
environ:
	.word 0

	.section .init
	.globl _start
	.type _start,@function

_start:
	/* Magic block required by the bootloader, otherwise harmless */
	la	s0, _start	/* Executable code base address */
	la	s1, _end	/* End of BSS section, word aligned */
	la	s0, __bss_start	/* Start of BSS section, NOT word aligned */

	/* Set global and thread pointers */
	la	gp, _gp	
	la	k1, thread0

	/* If no envp (a2) was provided, allocate an empty environ on stack */
	la	s4, environ
	bnez	a2, environ_ok
	addiu	sp, sp, -8	/* Keep the stack pointer 64-bit aligned */

	sw	zero, (sp)
	move	a2, sp
environ_ok:
	sw	a2, (s4)

	/* Save argc, argv, envp */
	move	s4, a0
	move	s5, a1
	move	s6, a2

	/* The loader doesn't bzero the BSS, so we must do it here. */
	j	bss_bzero_enter
	.set noreorder
bss_bzero_loop:
	sb	zero, (s0)
bss_bzero_enter:
	bne	s0, s1, bss_bzero_loop
	addiu	s0, s0, 1

	/* Call initializers / constructors */
	la	s0, __init_array_start
	la	s1, _fdata
	b	ctor_loop_enter
	move	s7, ra
ctor_loop:
	jalr	a0
	addiu	s0, s0, 4
ctor_loop_enter:
	bne	s0, s1,	ctor_loop
	lw	a0, (s0)

	/* Restore argc, argv, envp */
	move	a0, s4
	move	a1, s5
	move	a2, s6

	j	_C_LABEL(main)
	move	ra, s7
	.set reorder

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
	.option norelax
	/* Magic block required by the bootloader, otherwise harmless */
	lui	zero, 0xf32c0	/* f32c cookie */
	lui	s0, %hi(_start)	/* Executable code base address, absolute */
	addi	s0, s0, %lo(_start)
	lui	s0, %hi(__bss_start) /* Start of BSS section, absolute */
	addi	s0, s0, %lo(__bss_start) /* NOT word aligned */
	lui	s1, %hi(_end)	/* End of BSS section, absolute */
	addi	s1, s1, %lo(_end) /* word aligned */
	.option relax

	/* Set global and thread pointers */
	la	gp, __global_pointer$
	la	tp, thread0

	/* If no envp (a2) was provided, allocate an empty environ on stack */
	la	s4, environ
	bnez	a2, environ_ok
	addi	sp, sp, -8	/* Keep the stack pointer 64-bit aligned */
	sw	zero, (sp)
	move	a2, sp
environ_ok:
	sw	a2, (s4)

	/* Save argc, argv, envp, ra */
	move	s4, a0
	move	s5, a1
	move	s6, a2
	move	s7, ra

	/* The loader doesn't bzero the BSS, so we must do it here. */
	j	bss_bzero_enter
bss_bzero_loop:
	sb	zero, (s0)
	addi	s0, s0, 1
bss_bzero_enter:
	bne	s0, s1, bss_bzero_loop

	/* Call initializers / constructors */
	la	s0, __init_array_start
	la	s1, __init_array_end
	j	ctor_loop_enter
ctor_loop:
	lw	a0, (s0)
	addi	s0, s0, 4
	jalr	a0
ctor_loop_enter:
	bne	s0, s1,	ctor_loop

	/* Restore argc, argv, envp */
	move	a0, s4
	move	a1, s5
	move	a2, s6

	/* Done, jump into main */
	move	ra, s7
	j	main

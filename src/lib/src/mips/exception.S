/*-
 * Copyright (c) 2014-2015 Marko Zec, University of Zagreb
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
 *
 * $Id$
 */

#include <mips/asm.h>
#include <mips/regdef.h>
#include <mips/cpuregs.h>


#define	REGSIZE		4
#define	ISR_STACK_SIZE	512


	.bss
	.align 4

/*
 * _exception_regs MUST follow _exception_stack in memory!
 */
_exception_stack:	.space ISR_STACK_SIZE
_exception_regs:	.space REGSIZE * 22


	.text
	.set	reorder

/*
 * Prepare register context for executing ISR handlers and call isr_dispatch().
 */
LEAF(_exception_start)
	.set	noat

	/*
	 * Save register context. "S" registers will be saved by callees,
	 * so don't waste time and space on saving them here.
	 */
	la	k0, _exception_regs
	sw	ra, (0 * REGSIZE)(k0)
	sw	AT, (1 * REGSIZE)(k0)
	sw	v0, (2 * REGSIZE)(k0)
	sw	v1, (3 * REGSIZE)(k0)
	sw	a0, (4 * REGSIZE)(k0)
	sw	a1, (5 * REGSIZE)(k0)
	sw	a2, (6 * REGSIZE)(k0)
	sw	a3, (7 * REGSIZE)(k0)
	sw	t0, (8 * REGSIZE)(k0)
	sw	t1, (9 * REGSIZE)(k0)
	sw	t2, (10 * REGSIZE)(k0)
	sw	t3, (11 * REGSIZE)(k0)
	sw	t4, (12 * REGSIZE)(k0)
	sw	t5, (13 * REGSIZE)(k0)
	sw	t6, (14 * REGSIZE)(k0)
	sw	t7, (15 * REGSIZE)(k0)
	mfhi	v0
	mflo	v1
	sw	t8, (16 * REGSIZE)(k0)
	sw	t9, (17 * REGSIZE)(k0)
	sw	fp, (18 * REGSIZE)(k0)
	sw	v0, (19 * REGSIZE)(k0)	/* hi */
	sw	v1, (20 * REGSIZE)(k0)	/* lo */
#if 0
	sw	gp, (22 * REGSIZE)(k0)
#endif

	/* Mask IRQs */
	mfc0	v0, $MIPS_COP_0_CAUSE
	mfc0	v1, $MIPS_COP_0_STATUS
	and	a0, v1, v0
	srl	a0, a0, 8
	andi	a0, a0, 0xff

	/* Set up the exception stack */
	sw	sp, (21 * REGSIZE)(k0)
	move	sp, k0

	/* isr_dispatch() does the rest */
	jal	isr_dispatch

	/* Restore register context */
	lw	t0, (19 * REGSIZE)(k0)	/* hi */
	lw	t1, (20 * REGSIZE)(k0)	/* lo */
	lw	ra, (0 * REGSIZE)(k0)
	mthi	t0
	lw	AT, (1 * REGSIZE)(k0)
	lw	v0, (2 * REGSIZE)(k0)
	lw	v1, (3 * REGSIZE)(k0)
	mflo	zero			/* clear multiplier pipeline hazards */
	mtlo	t1
	lw	a0, (4 * REGSIZE)(k0)
	lw	a1, (5 * REGSIZE)(k0)
	lw	a2, (6 * REGSIZE)(k0)
	lw	a3, (7 * REGSIZE)(k0)
	lw	t0, (8 * REGSIZE)(k0)
	lw	t1, (9 * REGSIZE)(k0)
	lw	t2, (10 * REGSIZE)(k0)
	lw	t3, (11 * REGSIZE)(k0)
	lw	t4, (12 * REGSIZE)(k0)
	lw	t5, (13 * REGSIZE)(k0)
	lw	t6, (14 * REGSIZE)(k0)
	lw	t7, (15 * REGSIZE)(k0)
	lw	t8, (16 * REGSIZE)(k0)
	lw	t9, (17 * REGSIZE)(k0)
	lw	fp, (18 * REGSIZE)(k0)
	lw	sp, (21 * REGSIZE)(k0)
#if 0
	lw	gp, (22 * REGSIZE)(k0)
#endif

	mfc0	k0, $MIPS_COP_0_EXC_PC
	ei
	jr	k0
END(_exception_start)


/*
 * Set exception address, enable IRQ line (placed in a0).
 */
LEAF(enable_irq)
	la	a1, _exception_start
	mtc0	a1, $MIPS_COP_0_EBASE
	li	a1, 0x100
	sll	a1, a0
	mfc0	a0, $MIPS_COP_0_STATUS
	or	a0, a0, a1
	mtc0	a0, $MIPS_COP_0_STATUS
	jr	ra
END(enable_irq)


/*
 * Disable IRQ line (placed in a0).
 */
LEAF(disable_irq)
	li	a1, 0x100
	sll	a1, a0
	mfc0	a0, $MIPS_COP_0_STATUS
	not	a1
	and	a0, a0, a1
	mtc0	a0, $MIPS_COP_0_STATUS
	jr	ra
END(disable_irq)

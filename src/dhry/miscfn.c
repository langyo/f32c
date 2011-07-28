
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static char malloc_pool[128];
static int malloc_i = 0;

/* XXX this simplified malloc hack only works for the dhrystone benchmark! */
void *
malloc(int size __attribute__((unused)))
{
	void *addr;

	addr = &malloc_pool[malloc_i * 64];
	malloc_i ^= 1;

	return(addr);
}


int
strcmp(const char *s1, const char *s2)
{
#if 0
	int c1, c2;
 
	/* Check for aligned pointers for faster operation */
	if ((((int)s1 | (int)s2) & 3) == 0) {
		for (; (c1 = *((int *)s1)) == *((int *)s2);) {
			if ((c1 & 0x00ff0000) == 0)
				return(0);
			if ((c1 & 0x0000ff00) == 0)
				return(0);
			if ((c1 & 0x000000ff) == 0)
				return(0);
			if ((c1 & 0xff000000) == 0)
				return(0);
			s1 += 4;
			s2 += 4;
		}
	}

	do {
		c1 = *(const unsigned char *)s1++;
		c2 = *(const unsigned char *)s2++;
	} while (c1 != 0 && c1 == c2);
	return (c1 - c2);
#else
	int res;

	__asm (
		".set noreorder			\n"
		"	or	$2, $4, $5	\n"
		"	andi	$2, $2, 0x3	\n"
		"	bnez	$2, 3f		\n"
		"	lui	$6, 0x00ff	\n"
		"	lui	$7, 0xff00	\n"
		"	lw	$2, 0($4)	\n"
		"1:				\n"
		"	lw	$3, 0($5)	\n"
		"	addiu	$4, $4, 4	\n"
		"	bne	$2, $3, 2f	\n"
		"	and	$3, $2, $6	\n"
		"	beqz	$3, 5f		\n"
		"	and	$3, $2, $7	\n"
		"	beqz	$3, 5f		\n"
		"	andi	$3, $2, 0xff00	\n"
		"	beqz	$3, 5f		\n"
		"	andi	$3, $2, 0x00ff	\n"
		"	beqz	$3, 5f		\n"
		"	addiu	$5, $5, 4	\n"
		"	b	1b		\n"
		"	lw	$2, 0($4)	\n"
		"2:				\n"
		"	addiu	$4, $4, -4	\n"
		"3:				\n"
		"	lbu	$2, 0($4)	\n"
		"	lbu	$3, 0($5)	\n"
		"	beqz	$2, 4f		\n"
		"	addiu	$4, $4, 1	\n"
		"	beq	$2, $3, 3b	\n"
		"	addiu	$5, $5, 1	\n"
		"4:				\n"
		"	jr	$31		\n"
		"	subu	$2, $2, $3	\n"
		"5:				\n"
		"	jr	$31		\n"
		"	subu	$2, $2, $2	\n"
		: "=r" (res)
		: "r" (s1), "r" (s2)
	);

	/* XXX revisit return - missing a nop after jr ra */
	return(res);
#endif
}


/* memcpy() is required for -Os builds */
#ifdef memcpy
#undef memcpy
#endif
void
memcpy(char *dst, const char *src, int len)
{

	_memcpy(dst, src, len);
}


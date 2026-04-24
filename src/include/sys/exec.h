#ifndef _SYS_EXEC_H_
#define _SYS_EXEC_H_

#define	F32C_EXECINFO_COOKIE	0xf32cbeef
#define	F32C_EXECINFO_ADDR	0x80000000

struct f32c_execinfo {
	int	cookie;		/* F32C_EXECINFO_COOKIE */
	int	tries;		/* starts from 0, bumped by ROM bootloader */
	int	csum;		/* encompasses size, argc and all strings */
	int	size;		/* argv, envp, and all strings, word aligned */
	int	argc;
	char	**argv;
	char	**envp;
};

#endif

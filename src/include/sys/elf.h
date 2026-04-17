
#ifndef _SYS_ELF_H_
#define _SYS_ELF_H_ 1

int elfinfo(int, uint32_t *, uint32_t *, uint32_t *);
int elfload(int, char *, uint32_t, char *, uint32_t);

#endif /* !_SYS_ELF_H_ */

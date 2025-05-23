/*-
 * Copyright (c) 2013 - 2015 Marko Zec
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
 * Glue between POSIX unistd open etc. and FatFS interfaces.
 */

#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include <sys/file.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include <fatfs/diskio.h>

#include <dev/io.h>


static FATFS *ff_mounts[FF_VOLUMES];
static int ff_mounted;


static int
ffres2errno(int fferr)
{

	switch(fferr) {
	case FR_OK:
		return 0;
	case FR_DISK_ERR:
	case FR_INT_ERR:
	case FR_NOT_READY:
		errno = EIO;
		break;
	case FR_NO_FILE:
	case FR_NO_PATH:
		errno = ENOENT;
		break;
	case FR_INVALID_NAME:
		errno = ENAMETOOLONG;
		break;
	case FR_DENIED:
		errno = EACCES;
		break;
	case FR_EXIST:
		errno = EEXIST;
		break;
	case FR_WRITE_PROTECTED:
		errno = EROFS;
		break;
	case FR_INVALID_PARAMETER:
		errno = EINVAL;
		break;
	case FR_INVALID_OBJECT:
	case FR_INVALID_DRIVE:
	case FR_NOT_ENABLED:
	case FR_NO_FILESYSTEM:
	case FR_MKFS_ABORTED:
	case FR_TIMEOUT:
	case FR_LOCKED:
	case FR_NOT_ENOUGH_CORE:
	case FR_TOO_MANY_OPEN_FILES:
		/* XXX TODO resolve the above */
	default:
		errno = EOPNOTSUPP;
	}
	return -1;
}


static struct diskio_inst disk_i[FF_VOLUMES] = {
	{ .d_mnton = "C:" },
	{ .d_mnton = "D:" },
	{ .d_mnton = "F:" },
	{ .d_mnton = "R:" }
};


static void
check_automount(void)
{
	int i;

	if (ff_mounted)
		return;

	for (i = 0; i < FF_VOLUMES; i++) {
		if (ff_mounts[i] != NULL)
			continue;
		ff_mounts[i] = malloc(sizeof(FATFS));
		if (ff_mounts[i] == NULL)
			return;
		if (i == 0)
			diskio_attach_flash(&disk_i[i],
			    IO_SPI_FLASH, /* SPI port */
			    0, /* SPI slave unit */
			    1024 * 1024, /* offset from media start, bytes*/
			    3 * 1024 * 1024 /* block size, bytes*/);
		else if (i == 1)
			diskio_attach_sdcard(&disk_i[i],
			    IO_SPI_SDCARD, /* SPI port */
			    0); /* SPI slave unit */
		else if (i == 2)
			diskio_attach_fram(&disk_i[i],
			    IO_SPI_FLASH, /* SPI port */
			    1, /* SPI slave unit */
			    0, /* offset from media start, bytes*/
			    512 * 1024 /* block size, bytes*/);
		else
			diskio_attach_ram(&disk_i[i],
			    malloc(i * 1024 * 1024), /* base addr*/
			    i * 1024 * 1024 /* size, bytes */);
		f_mount(ff_mounts[i], disk_i[i].d_mnton, 0);
	}
	ff_mounted = 1;
}


int
creat(const char *path, mode_t mode __unused)
{

	check_automount();
	return (open(path, O_CREAT | O_TRUNC | O_WRONLY));
}


off_t
lseek(int d, off_t offset, int whence)
{
	struct task *ts = TD_TASK(curthread);
	FIL *ffp;
	FRESULT f_res;

	/* XXX hack for stdin, stdout, stderr */
	if (d >= 0 && d <= 2)
		return (-1);

	if (d < 3 || d >= ts->ts_maxfiles || ts->ts_files[d] == NULL) {
		errno = EBADF;
		return (-1);
	}

	ffp = ts->ts_files[d]->f_priv;
	switch (whence) {
	case SEEK_SET:
		break;
	case SEEK_CUR:
		offset = f_tell(ffp) + offset;
		break;
	case SEEK_END:
		offset = f_size(ffp) + offset; /* XXX revisit */
		break;
	default:
		errno = EINVAL;
		return (-1);
	}

	f_res = f_lseek(ffp, offset);
	if (f_res != FR_OK)
		return(ffres2errno(f_res));
	return ((int) f_tell(ffp));
}


int
unlink(const char *path)
{
#if !defined(_FS_READONLY) || (_FS_READONLY == 0)
	FRESULT f_res;

	check_automount();
	f_res = f_unlink(path);
	return(ffres2errno(f_res));
#else
	return (-1);
#endif
}


int
chdir(const char *path) {
	int res;

	check_automount();
	if (path[1] == ':' && path[2] == 0)
		res = f_chdrive(path);
	else
		res = f_chdir(path);
	return(ffres2errno(res));
}


char *
getcwd(char *buf, size_t size)
{
	int res;

	check_automount();

	if (buf == NULL)
		buf = malloc(FF_MAX_LFN);

	if (buf == NULL) {
		errno = ENOMEM;
		return buf;
	}

	res = f_getcwd(buf, size);
	ffres2errno(res);
	return buf;
};


int
mkdir(const char *path, mode_t mode)
{
	int res;

	check_automount();
	res = f_mkdir(path);
	return(ffres2errno(res));
};


int
rmdir(const char *path)
{
	int res;

	check_automount();
	res = f_rmdir(path);
	return(ffres2errno(res));
};


int
rename(const char *from, const char *to)
{
	int res;

	check_automount();
	res = f_rename(from, to);
	return(ffres2errno(res));
};


DIR *
opendir(const char *path)
{
	int res;
	DIR *dirp = malloc(sizeof(DIR));

	check_automount();
	if (dirp == NULL) {
		errno = EINVAL;
		return dirp;
	}

	res = f_opendir(&dirp->ff_dir, path);
	if (ffres2errno(res) != 0) {
		free(dirp);
		return NULL;
	}

	return dirp;
};


struct dirent *
readdir(DIR *dirp)
{
	int res;

	if (dirp == NULL) {
		errno = EINVAL;
		return NULL;
	}

	res = f_readdir(&dirp->ff_dir, &dirp->ff_info);
	if (ffres2errno(res) != 0 || dirp->ff_info.fname[0] == 0)
		return NULL;

	if (dirp->ff_info.fattrib & AM_DIR)
		dirp->de.d_type = DT_DIR;
	else
		dirp->de.d_type = DT_REG;
	dirp->de.d_namlen = strlen(dirp->ff_info.fname);
	if (dirp->de.d_namlen > sizeof(dirp->de.d_name) - 1)
		dirp->de.d_namlen = sizeof(dirp->de.d_name) - 1;
	memcpy(dirp->de.d_name, dirp->ff_info.fname, dirp->de.d_namlen);
	dirp->de.d_name[dirp->de.d_namlen] = 0;

	return &dirp->de;
};


int
closedir(DIR *dirp)
{
	int res;

	res = f_closedir(&dirp->ff_dir);
	free(dirp);
	return(ffres2errno(res));
};


int
ff_close(struct file *fp)
{
	FIL *ffp = fp->f_priv;
	FRESULT f_res;

	f_res = f_close(ffp);
	return(ffres2errno(f_res));
}


ssize_t
ff_read(struct file *fp, void *buf, size_t nbytes)
{
	FIL *ffp = fp->f_priv;
	FRESULT f_res;
	size_t got;

	f_res = f_read(ffp, buf, nbytes, &got);
	if (f_res == FR_OK)
		return (got);
	return(ffres2errno(f_res));
}


ssize_t
ff_write(struct file *fp, const void *buf, size_t nbytes)
{
	FIL *ffp = fp->f_priv;
	FRESULT f_res;
	size_t wrote = -1;

#if !defined(_FS_READONLY) || (_FS_READONLY == 0)
	f_res = f_write(ffp, buf, nbytes, &wrote);
	if (f_res != FR_OK)
		return(ffres2errno(f_res));
#else
	errno = EIO;
#endif
	return (wrote);
}


static struct fileops ff_fileops = {
	.fo_close = &ff_close,
	.fo_read = &ff_read,
	.fo_write = &ff_write,
};


int
ff_open(struct file *fp, const char *path, int flags, ...)
{
	FIL *ffp;
	int res, ff_flags;

	check_automount();

	/* Map open() flags to f_open() flags */
	ff_flags = ((flags & O_ACCMODE) + 1);
#if !defined(_FS_READONLY) || (_FS_READONLY == 0)
	if (flags & (O_CREAT | O_TRUNC))
		ff_flags |= FA_CREATE_ALWAYS;
	else if (flags & O_CREAT)
		ff_flags |= FA_OPEN_ALWAYS;
#endif

	ffp = malloc(sizeof(FIL));
	if (ffp == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	fp->f_ops = &ff_fileops;
	fp->f_priv = ffp;
	res = f_open(ffp, path, ff_flags);
	return(ffres2errno(res));
}


int
stat(const char *path, struct stat *sb)
{
	FILINFO fno;
	int res;
	struct tm tm;

	res = f_stat(path, &fno);
	if (res)
		return (res);

	bzero(sb, sizeof(*sb));
	sb->st_size = fno.fsize;

	tm.tm_sec = (fno.ftime & 0x1f) * 2;
	tm.tm_min = (fno.ftime >> 5) & 0x3f;
	tm.tm_hour = fno.ftime >> 11;
	tm.tm_mday = fno.fdate & 0x1f;
	tm.tm_mon = ((fno.fdate >> 5) & 0xf) - 1;
	tm.tm_year = (fno.fdate >> 9) + 80;

	sb->st_mtime = timegm(&tm);
	sb->st_atime = sb->st_mtime;
	sb->st_ctime = sb->st_mtime;

	if (fno.fattrib & AM_DIR)
		sb->st_mode |= S_IFDIR;
	sb->st_mode |= S_IRUSR | S_IRGRP | S_IROTH;
	if ((fno.fattrib & AM_RDO) == 0)
		sb->st_mode |= S_IWUSR | S_IWGRP | S_IWOTH;
	if (fno.fattrib & AM_SYS)
		sb->st_mode |= S_IXUSR | S_IXGRP | S_IXOTH;

	return(0);
}


int
getfsstat(struct statfs *buf, long bufsize, int mode)
{
	int i, res, mounts;
	FATFS *fs;
	DWORD free_clus, tot_sec, free_sec;

	for (i = 0, mounts = 0; i < FF_VOLUMES; i++) {
		if (ff_mounts[i] == NULL)
			continue;
		res = f_getfree(disk_i[i].d_mnton, &free_clus, &fs);
		if (res)
			continue;
		mounts++;
		if (buf == NULL)
			continue;
		tot_sec = (fs->n_fatent - 2) * fs->csize;
		free_sec = free_clus * fs->csize;
		buf[mounts - 1].f_bsize = fs->ssize;
		buf[mounts - 1].f_blocks = tot_sec;
		buf[mounts - 1].f_bavail = free_sec;
		buf[mounts - 1].f_bfree = free_sec;
		strcpy(buf[mounts - 1].f_mntfromname, disk_i[i].d_mntfrom);
		strcpy(buf[mounts - 1].f_mntonname, disk_i[i].d_mnton);
	}

	return(mounts);
}

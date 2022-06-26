//#include <receivelog.h>
//#include <streamutil.h>
#include <walmethods.h>
#include <unistd.h>
#include "libpq-fe.h"
#include <stddef.h>
#include <errno.h>

#include <pgmoneta.h>
#include <logging.h>
#include <management.h>
#include <memory.h>
#include <message.h>
#include <network.h>
#include <prometheus.h>
#include <security.h>
#include <server.h>
#include <stdlib.h>
#include <stdio.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h> 
/*
#include <wal.h>
#include <backup_wal.h>
#include <utils.h>
#include <xlogdefs.h>
//#include <port.h>
#include <assert.h>
//#include <streamutil.h>
//#include <xlogdefs.h>
//#include <walmethods.h>

#include <ev.h>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/ssl.h>
*/

    typedef long off_t;

//konglx 
//#define errno -1//(*_errno())

#define PG_BINARY	0

#define MAXPGPATH		1024


// Error codes
#define EPERM           1
#define ENOENT          2
#define ESRCH           3
#define EINTR           4
#define EIO             5
#define ENXIO           6
#define E2BIG           7
#define ENOEXEC         8
#define EBADF           9
#define ECHILD          10
#define EAGAIN          11
#define ENOMEM          12
#define EACCES          13
#define EFAULT          14
#define EBUSY           16
#define EEXIST          17
#define EXDEV           18
#define ENODEV          19
#define ENOTDIR         20
#define EISDIR          21
#define ENFILE          23
#define EMFILE          24
#define ENOTTY          25
#define EFBIG           27
#define ENOSPC          28
#define ESPIPE          29
#define EROFS           30
#define EMLINK          31
#define EPIPE           32
#define EDOM            33
#define EDEADLK         36
#define ENAMETOOLONG    38
#define ENOLCK          39
#define ENOSYS          40
#define ENOTEMPTY       41

/*
 * Flags for pg_malloc_extended and palloc_extended, deliberately named
 * the same as the backend flags.
 */
#define MCXT_ALLOC_HUGE			0x01	/* allow huge allocation (> 1 GB) not
										 * actually used for frontends */
#define MCXT_ALLOC_NO_OOM		0x02	/* no failure if out-of-memory */
#define MCXT_ALLOC_ZERO			0x04	/* zero allocated memory */




typedef long long int int64;

//typedef enum __bool { false = 0, true = 1, } bool;


//konglx created: here 
#define XLOG_BLCKSZ 8192

/* Same, but for an XLOG_BLCKSZ-sized buffer */
typedef union PGAlignedXLogBlock
{
	char		data[XLOG_BLCKSZ];
	double		force_align_d;
	int64		force_align_i64;
} PGAlignedXLogBlock;


/*
 * Local file handle
 */
typedef struct DirectoryMethodFile
{
	int			fd;
	off_t		currpos;
	char	   *pathname;
	char	   *fullpath;
	char	   *temp_suffix;
#ifdef HAVE_LIBZppp
	gzFile		gzfp;
#endif
} DirectoryMethodFile;


/*
 * Global static data for this method
 */
typedef struct DirectoryMethodData
{
	char	   *basedir;
	int			compression;
	bool		sync;
	const char *lasterrstring;	/* if set, takes precedence over lasterrno */
	int			lasterrno;
} DirectoryMethodData;

static DirectoryMethodData *dir_data = NULL;
#define dir_clear_error() \
	(dir_data->lasterrstring = NULL, dir_data->lasterrno = 0)
#define dir_set_error(msg) \
	(dir_data->lasterrstring = _(msg))

/*
void
pg_free(void *ptr)
{
	if (ptr != NULL)
		free(ptr);
}
*/

static inline void *
pg_malloc_internal(size_t size, int flags)
{
	void	   *tmp;

	/* Avoid unportable behavior of malloc(0) */
	if (size == 0)
		size = 1;
	tmp = malloc(size);
	if (tmp == NULL)
	{
		if ((flags & MCXT_ALLOC_NO_OOM) == 0)
		{
			fprintf(stderr, ("out of memory\n"));//_("out of memory\n"));
			exit(EXIT_FAILURE);
		}
		return NULL;
	}

	if ((flags & MCXT_ALLOC_ZERO) != 0)
		//MemSet(tmp, 0, size);
        memset(tmp, 0, size);
	return tmp;
}

void *
pg_malloc0(size_t size)
{
	return pg_malloc_internal(size, MCXT_ALLOC_ZERO);
}

//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Flags
//
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#define _S_IFMT   0xF000 // File type mask
#define _S_IFDIR  0x4000 // Directory
#define _S_IFCHR  0x2000 // Character special
#define _S_IFIFO  0x1000 // Pipe
#define _S_IFREG  0x8000 // Regular
#define _S_IREAD  0x0100 // Read permission, owner
#define _S_IWRITE 0x0080 // Write permission, owner
#define _S_IEXEC  0x0040 // Execute/search permission, owner


/* These macros are not provided by older MinGW, nor by MSVC */
#ifndef S_IRUSR
#define S_IRUSR _S_IREAD
#endif
#ifndef S_IWUSR
#define S_IWUSR _S_IWRITE
#endif
#ifndef S_IXUSR
#define S_IXUSR _S_IEXEC
#endif
#ifndef S_IRWXU
#define S_IRWXU (S_IRUSR | S_IWUSR | S_IXUSR)
#endif
#ifndef S_IRGRP
#define S_IRGRP 0
#endif
#ifndef S_IWGRP
#define S_IWGRP 0
#endif
#ifndef S_IXGRP
#define S_IXGRP 0
#endif
#ifndef S_IRWXG
#define S_IRWXG 0
#endif
#ifndef S_IROTH
#define S_IROTH 0
#endif
#ifndef S_IWOTH
#define S_IWOTH 0
#endif
#ifndef S_IXOTH
#define S_IXOTH 0
#endif
#ifndef S_IRWXO
#define S_IRWXO 0
#endif
#ifndef S_ISDIR
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif
#ifndef S_ISREG
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif

/*
 * Mode mask for data directory permissions that only allows the owner to
 * read/write directories and files.
 *
 * This is the default.
 */
#define PG_MODE_MASK_OWNER		    (S_IRWXG | S_IRWXO)

/*
 * Mode mask for data directory permissions that also allows group read/execute.
 */
#define PG_MODE_MASK_GROUP			(S_IWGRP | S_IRWXO)

/* Default mode for creating directories */
#define PG_DIR_MODE_OWNER			S_IRWXU

/* Mode for creating directories that allows group read/execute */
#define PG_DIR_MODE_GROUP			(S_IRWXU | S_IRGRP | S_IXGRP)

/* Default mode for creating files */
#define PG_FILE_MODE_OWNER		    (S_IRUSR | S_IWUSR)

/* Mode for creating files that allows group read */
#define PG_FILE_MODE_GROUP			(S_IRUSR | S_IWUSR | S_IRGRP)


static char *
dir_get_file_name(const char *pathname, const char *temp_suffix)
{
    pgmoneta_log_info("konglx: dir_get_file_name begin to exec");
	char	   *filename = pg_malloc0(MAXPGPATH * sizeof(char));

	snprintf(filename, MAXPGPATH, "%s%s%s",
			 pathname, dir_data->compression > 0 ? ".gz" : "",
			 temp_suffix ? temp_suffix : "");
    pgmoneta_log_info("konglx:dir_get_file_name return filename %s",filename);
	return filename;
}

#define ERROR		21			/* user error - abort transaction; return to
								 * known state */
/*
 * fsync_fname -- Try to fsync a file or directory
 *
 * Ignores errors trying to open unreadable files, or trying to fsync
 * directories on systems where that isn't allowed/required.  All other errors
 * are fatal.
 */
int
fsync_fname(const char *fname, bool isdir)
{
	int			fd;
	int			flags;
	int			returncode;

	/*
	 * Some OSs require directories to be opened read-only whereas other
	 * systems don't allow us to fsync files opened read-only; so we need both
	 * cases here.  Using O_RDWR will cause us to fail to fsync files that are
	 * not writable by our userid, but we assume that's OK.
	 */
	flags = PG_BINARY;
	if (!isdir)
		flags |= O_RDWR;
	else
		flags |= O_RDONLY;

	/*
	 * Open the file, silently ignoring errors about unreadable files (or
	 * unsupported operations, e.g. opening a directory under Windows), and
	 * logging others.
	 */
	fd = open(fname, flags, 0);
	if (fd < 0)
	{
		if (errno == EACCES || (isdir && errno == EISDIR))
			return 0;
		//pg_log_error("could not open file \"%s\": %m", fname);
        pgmoneta_log_error("could not open file \"%s\": %m", fname);
		return -1;
	}

	returncode = fsync(fd);

	/*
	 * Some OSes don't allow us to fsync directories at all, so we can ignore
	 * those errors. Anything else needs to be reported.
	 */
	if (returncode != 0 && !(isdir && (errno == EBADF || errno == EINVAL)))
	{
		//pg_log_fatal("could not fsync file \"%s\": %m", fname);
        pgmoneta_log_fatal("could not fsync file \"%s\": %m", fname);
		(void) close(fd);
		exit(EXIT_FAILURE);
	}

	(void) close(fd);
	return 0;
}

/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 * Function creation history:  http://www.gratisoft.us/todd/papers/strlcpy.html
 */
size_t
strlcpy(char *dst, const char *src, size_t siz)
{
	char	   *d = dst;
	const char *s = src;
	size_t		n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0)
	{
		while (--n != 0)
		{
			if ((*d++ = *s++) == '\0')
				break;
		}
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0)
	{
		if (siz != 0)
			*d = '\0';			/* NUL-terminate dst */
		while (*s++)
			;
	}

	return (s - src - 1);		/* count does not include NUL */
}
#define skip_drive(path)	(path)
#define IS_DIR_SEP(ch)	((ch) == '/' || (ch) == '\\')
/*
 *	trim_directory
 *
 *	Trim trailing directory from path, that is, remove any trailing slashes,
 *	the last pathname component, and the slash just ahead of it --- but never
 *	remove a leading slash.
 */
static void
trim_directory(char *path)
{
	char	   *p;

	path = skip_drive(path);

	if (path[0] == '\0')
		return;

	/* back up over trailing slash(es) */
	for (p = path + strlen(path) - 1; IS_DIR_SEP(*p) && p > path; p--)
		;
	/* back up over directory name */
	for (; !IS_DIR_SEP(*p) && p > path; p--)
		;
	/* if multiple slashes before directory name, remove 'em all */
	for (; p > path && IS_DIR_SEP(*(p - 1)); p--)
		;
	/* don't erase a leading slash */
	if (p == path && IS_DIR_SEP(*p))
		p++;
	*p = '\0';
}

/*
 * get_parent_directory
 *
 * Modify the given string in-place to name the parent directory of the
 * named file.
 *
 * If the input is just a file name with no directory part, the result is
 * an empty string, not ".".  This is appropriate when the next step is
 * join_path_components(), but might need special handling otherwise.
 *
 * Caution: this will not produce desirable results if the string ends
 * with "..".  For most callers this is not a problem since the string
 * is already known to name a regular file.  If in doubt, apply
 * canonicalize_path() first.
 */
void
get_parent_directory(char *path)
{
	trim_directory(path);
}

/*
 * fsync_parent_path -- fsync the parent path of a file or directory
 *
 * This is aimed at making file operations persistent on disk in case of
 * an OS crash or power failure.
 */
int
fsync_parent_path(const char *fname)
{
	char		parentpath[MAXPGPATH];

	strlcpy(parentpath, fname, MAXPGPATH);
    //strcpy(parentpath, fname, MAXPGPATH);
	get_parent_directory(parentpath);

	/*
	 * get_parent_directory() returns an empty string if the input argument is
	 * just a file name (see comments in path.c), so handle that as being the
	 * current directory.
	 */
	if (strlen(parentpath) == 0)
        //strcpy(parentpath, ".", MAXPGPATH);
		strlcpy(parentpath, ".", MAXPGPATH);

	if (fsync_fname(parentpath, true) != 0)
		return -1;

	return 0;
}


/*
 * "Safe" wrapper around strdup().
 */
char *
pg_strdup(const char *in)
{
	char	   *tmp;

	if (!in)
	{
		fprintf(stderr,
				("cannot duplicate null pointer (internal error)\n"));
		exit(EXIT_FAILURE);
	}
	tmp = strdup(in);
	if (!tmp)
	{
		fprintf(stderr, ("out of memory\n"));
		exit(EXIT_FAILURE);
	}
	return tmp;
}



static Walfile
dir_open_for_write(const char *pathname, const char *temp_suffix, size_t pad_to_size)
{
	char		tmppath[MAXPGPATH];
	char	   *filename;
	int			fd;
	DirectoryMethodFile *f;
#ifdef HAVE_LIBZppp
	gzFile		gzfp = NULL;
#endif

	dir_clear_error();

	filename = dir_get_file_name(pathname, temp_suffix);
	snprintf(tmppath, sizeof(tmppath), "%s/%s",
			 dir_data->basedir, filename);
	pg_free(filename);
    pgmoneta_log_info("konglx: dir_open_for_write(): tmppath %s" , tmppath);
	/*
	 * Open a file for non-compressed as well as compressed files. Tracking
	 * the file descriptor is important for dir_sync() method as gzflush()
	 * does not do any system calls to fsync() to make changes permanent on
	 * disk.
	 */
	fd = open(tmppath, O_WRONLY | O_CREAT | PG_BINARY, PG_FILE_MODE_OWNER);//pg_file_create_mode);
	if (fd < 0)
	{
		dir_data->lasterrno = errno;
        pgmoneta_log_error("konglx: dir_open_for_write file open is error");
		return NULL;
	}

#ifdef HAVE_LIBZppp
	if (dir_data->compression > 0)
	{
		gzfp = gzdopen(fd, "wb");
		if (gzfp == NULL)
		{
			dir_data->lasterrno = errno;
			close(fd);
			return NULL;
		}

		if (gzsetparams(gzfp, dir_data->compression,
						Z_DEFAULT_STRATEGY) != Z_OK)
		{
			dir_data->lasterrno = errno;
			gzclose(gzfp);
			return NULL;
		}
	}
#endif

	/* Do pre-padding on non-compressed files */
	if (pad_to_size && dir_data->compression == 0)
	{
		PGAlignedXLogBlock zerobuf;
		int			bytes;

		memset(zerobuf.data, 0, XLOG_BLCKSZ);
		for (bytes = 0; bytes < pad_to_size; bytes += XLOG_BLCKSZ)
		{
			errno = 0;
			if (write(fd, zerobuf.data, XLOG_BLCKSZ) != XLOG_BLCKSZ)
			{
                pgmoneta_log_error("konglx: dir_open_for_write write is error");
				/* If write didn't set errno, assume problem is no disk space */
				dir_data->lasterrno = errno ? errno : ENOSPC;
				close(fd);
				return NULL;
			}
		}

		if (lseek(fd, 0, SEEK_SET) != 0)
		{
			dir_data->lasterrno = errno;
			close(fd);
			return NULL;
		}
	}

	/*
	 * fsync WAL file and containing directory, to ensure the file is
	 * persistently created and zeroed (if padded). That's particularly
	 * important when using synchronous mode, where the file is modified and
	 * fsynced in-place, without a directory fsync.
	 */
	if (dir_data->sync)
	{
		if (fsync_fname(tmppath, false) != 0 ||
			fsync_parent_path(tmppath) != 0)
		{
			dir_data->lasterrno = errno;
#ifdef HAVE_LIBZ
			if (dir_data->compression > 0)
				gzclose(gzfp);
			else
#endif
				close(fd);
			return NULL;
		}
	}

	f = pg_malloc0(sizeof(DirectoryMethodFile));
#ifdef HAVE_LIBZ
	if (dir_data->compression > 0)
		f->gzfp = gzfp;
#endif
	f->fd = fd;
	f->currpos = 0;
	f->pathname = pg_strdup(pathname);
	f->fullpath = pg_strdup(tmppath);
	if (temp_suffix)
		f->temp_suffix = pg_strdup(temp_suffix);

	return f;
}



static ssize_t
dir_write(Walfile f, const void *buf, size_t count)
{
    pgmoneta_log_info("begin write in dir_write");
	ssize_t		r;
	DirectoryMethodFile *df = (DirectoryMethodFile *) f;

	//Assert(f != NULL);
	//dir_clear_error();

#ifdef HAVE_LIBZppp
	if (dir_data->compression > 0)
	{
		errno = 0;
		r = (ssize_t) gzwrite(df->gzfp, buf, count);
		if (r != count)
		{
			/* If write didn't set errno, assume problem is no disk space */
			dir_data->lasterrno = errno ? errno : ENOSPC;
		}
	}
	else
#endif
	{
		errno = 0;
		r = write(df->fd, buf, count);
		if (r != count)
		{
			/* If write didn't set errno, assume problem is no disk space */
			dir_data->lasterrno = errno ? errno : ENOSPC;
		}
	}
	pgmoneta_log_info("konglx: df->currpos += r; %d", r);
	if (r > 0)
		df->currpos += r;
	return r;
}


static off_t
dir_get_current_pos(Walfile f)
{
	//Assert(f != NULL);
    //assert(f != NULL);
	dir_clear_error();

	/* Use a cached value to prevent lots of reseeks */
	return ((DirectoryMethodFile *) f)->currpos;
}

static ssize_t
dir_get_file_size(const char *pathname)
{
	struct stat statbuf;
	char		tmppath[MAXPGPATH];

	snprintf(tmppath, sizeof(tmppath), "%s/%s",
			 dir_data->basedir, pathname);

	if (stat(tmppath, &statbuf) != 0)
	{
		dir_data->lasterrno = errno;
		return -1;
	}

	return statbuf.st_size;
}



static int
dir_sync(Walfile f)
{
	int			r;

	//Assert(f != NULL);
	dir_clear_error();

	if (!dir_data->sync)
		return 0;

#ifdef HAVE_LIBZppp
	if (dir_data->compression > 0)
	{
		if (gzflush(((DirectoryMethodFile *) f)->gzfp, Z_SYNC_FLUSH) != Z_OK)
		{
			dir_data->lasterrno = errno;
			return -1;
		}
	}
#endif

	r = fsync(((DirectoryMethodFile *) f)->fd);
	if (r < 0)
		dir_data->lasterrno = errno;
	return r;
}

static bool
dir_existsfile(const char *pathname)
{
	char		tmppath[MAXPGPATH];
	int			fd;
    pgmoneta_log_info("konglx: begin to dir_existsfile");
	dir_clear_error();

	snprintf(tmppath, sizeof(tmppath), "%s/%s",
			 dir_data->basedir, pathname);

	fd = open(tmppath, O_RDONLY | PG_BINARY, 0);
    pgmoneta_log_info("konglx: dir_existsfile dir_existsfile is %d",fd);
	if (fd < 0)
		return false;
	close(fd);
	return true;
}

static bool
dir_finish(void)
{
	dir_clear_error();

	if (dir_data->sync)
	{
		/*
		 * Files are fsynced when they are closed, but we need to fsync the
		 * directory entry here as well.
		 */
		if (fsync_fname(dir_data->basedir, true) != 0)
		{
			dir_data->lasterrno = errno;
			return false;
		}
	}
	return true;
}

/*
 * durable_rename -- rename(2) wrapper, issuing fsyncs required for durability
 *
 * Wrapper around rename, similar to the backend version.
 */
int
durable_rename(const char *oldfile, const char *newfile)
{
	int			fd;

	/*
	 * First fsync the old and target path (if it exists), to ensure that they
	 * are properly persistent on disk. Syncing the target file is not
	 * strictly necessary, but it makes it easier to reason about crashes;
	 * because it's then guaranteed that either source or target file exists
	 * after a crash.
	 */
	if (fsync_fname(oldfile, false) != 0)
		return -1;

	fd = open(newfile, PG_BINARY | O_RDWR, 0);
	if (fd < 0)
	{
		if (errno != ENOENT)
		{
			//pg_log_error("could not open file \"%s\": %m", newfile);
			pgmoneta_log_error("could not open file \"%s\": %m", newfile);
			return -1;
		}
	}
	else
	{
		if (fsync(fd) != 0)
		{
			//pg_log_fatal("could not fsync file \"%s\": %m", newfile);
			pgmoneta_log_fatal("could not fsync file \"%s\": %m", newfile);
			close(fd);
			exit(EXIT_FAILURE);
		}
		close(fd);
	}

	/* Time to do the real deal... */
	if (rename(oldfile, newfile) != 0)
	{
		//pg_log_error("could not rename file \"%s\" to \"%s\": %m",
		//			 oldfile, newfile);
		pgmoneta_log_error("could not rename file \"%s\" to \"%s\": %m",
					 oldfile, newfile);
		return -1;
	}

	/*
	 * To guarantee renaming the file is persistent, fsync the file with its
	 * new name, and its containing directory.
	 */
	if (fsync_fname(newfile, false) != 0)
		return -1;

	if (fsync_parent_path(newfile) != 0)
		return -1;

	return 0;
}

static int
dir_close(Walfile f, WalCloseMethod method)
{
	int			r;
	DirectoryMethodFile *df = (DirectoryMethodFile *) f;
	char		tmppath[MAXPGPATH];
	char		tmppath2[MAXPGPATH];

	//Assert(f != NULL);
	dir_clear_error();

#ifdef HAVE_LIBZppp
	if (dir_data->compression > 0)
	{
		errno = 0;				/* in case gzclose() doesn't set it */
		r = gzclose(df->gzfp);
	}
	else
#endif
		r = close(df->fd);

	if (r == 0)
	{
		/* Build path to the current version of the file */
		if (method == CLOSE_NORMAL && df->temp_suffix)
		{
			char	   *filename;
			char	   *filename2;

			/*
			 * If we have a temp prefix, normal operation is to rename the
			 * file.
			 */
			filename = dir_get_file_name(df->pathname, df->temp_suffix);
			snprintf(tmppath, sizeof(tmppath), "%s/%s",
					 dir_data->basedir, filename);
			pg_free(filename);

			/* permanent name, so no need for the prefix */
			filename2 = dir_get_file_name(df->pathname, NULL);
			snprintf(tmppath2, sizeof(tmppath2), "%s/%s",
					 dir_data->basedir, filename2);
			pg_free(filename2);
			r = durable_rename(tmppath, tmppath2);
		}
		else if (method == CLOSE_UNLINK)
		{
			char	   *filename;

			/* Unlink the file once it's closed */
			filename = dir_get_file_name(df->pathname, df->temp_suffix);
			snprintf(tmppath, sizeof(tmppath), "%s/%s",
					 dir_data->basedir, filename);
			pg_free(filename);
			r = unlink(tmppath);
		}
		else
		{
			/*
			 * Else either CLOSE_NORMAL and no temp suffix, or
			 * CLOSE_NO_RENAME. In this case, fsync the file and containing
			 * directory if sync mode is requested.
			 */
			if (dir_data->sync)
			{
				r = fsync_fname(df->fullpath, false);
				if (r == 0)
					r = fsync_parent_path(df->fullpath);
			}
		}
	}

	if (r != 0)
		dir_data->lasterrno = errno;

	pg_free(df->pathname);
	pg_free(df->fullpath);
	if (df->temp_suffix)
		pg_free(df->temp_suffix);
	pg_free(df);

	return r;
}


WalWriteMethod *
CreateWalDirectoryMethod(const char *basedir, int compression, bool sync)
{
	WalWriteMethod *method;

	method = pg_malloc0(sizeof(WalWriteMethod));
	method->open_for_write = dir_open_for_write;
	method->write = dir_write;
	method->get_current_pos = dir_get_current_pos;
	method->get_file_size = dir_get_file_size;
	method->get_file_name = dir_get_file_name;
	//method->compression = dir_compression;
	method->close = dir_close;
	method->sync = dir_sync;
	method->existsfile = dir_existsfile;
	method->finish = dir_finish;
	//method->getlasterror = dir_getlasterror;

	dir_data = pg_malloc0(sizeof(DirectoryMethodData));
	dir_data->compression = compression;
	dir_data->basedir = pg_strdup(basedir);
	dir_data->sync = sync;

	return method;
}


void
FreeWalDirectoryMethod(void)
{
	pg_free(dir_data->basedir);
	pg_free(dir_data);
	dir_data = NULL;
}

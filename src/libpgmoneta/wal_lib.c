
/* pgmoneta */
#include <pgmoneta.h>
#include <logging.h>
#include <management.h>
#include <memory.h>
#include <message.h>
#include <network.h>
#include <prometheus.h>
#include <security.h>
#include <server.h>
#include <wal.h>
#include <wal_lib.h>
#include <utils.h>
#include <xlogdefs.h>
#include <dirent.h>
#include <errno.h>
//#include <port.h>
#include <assert.h>
//#include <streamutil.h>
//#include <xlogdefs.h>
//#include <wal_method.h>
/* system */
#include <ev.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/ssl.h>

#include "libpq-fe.h"

PGconn* conn;
#define PGINVALID_SOCKET (-1)

const char *progname;
char *connection_string;
char *dbhost;
char *dbuser;
char *dbport;
char *dbname;
int	dbgetpassword;
uint32 WalSegSz;

/* Global options */
static char *basedir = NULL;
static int	verbose = 0;
static int	compresslevel = 0;
static int	noloop = 0;
static int	standby_message_timeout = 10 * 1000;	/* 10 sec = default */
static volatile bool time_to_stop = false;
static bool do_create_slot = false;
static bool slot_exists_ok = false;
static bool do_drop_slot = false;
static bool do_sync = true;
static bool synchronous = false;
static char *replication_slot = NULL;
static XLogRecPtr endpos = InvalidXLogRecPtr;
/*
CMD: PGPASSWORD="secretpassword" /usr/pgsql-14/bin//pg_receivewal -
h localhost
 -p 5432 
 -U repl 
 --no-loop 
 --no-password 
 -D /home/kk/GSoC/upload/pgmoneta-plus/backup/primary/wal/
*/


/*
 * MAXPGPATH: standard size of a pathname buffer in PostgreSQL (hence,
 * maximum usable pathname length is one less).
 *
 * We'd use a standard system header symbol for this, if there weren't
 * so many to choose from: MAXPATHLEN, MAX_PATH, PATH_MAX are all
 * defined by different "standards", and often have different values
 * on the same platform!  So we just punt and use a reasonably
 * generous setting here.
 */
#define MAXPGPATH		1024

#define USECS_PER_SEC	INT64CONST(1000000)

/* Time to sleep between reconnection attempts */
#define RECONNECT_SLEEP_TIME 5

//#define errno (*_errno())

typedef int pgsocket;

/* fd and filename for currently open WAL file */
static Walfile *walfile = NULL;
static char current_walfile_name[MAXPGPATH] = "";
static bool reportFlushPosition = false;
static XLogRecPtr lastFlushPosition = InvalidXLogRecPtr;

static bool still_sending = true;	/* feedback still needs to be sent? */

typedef int64 TimestampTz;


#define XLogSegmentOffset(xlogptr, wal_segsz_bytes)	\
	((xlogptr) & ((wal_segsz_bytes) - 1))


static void
exit_nicely(PGconn *conn)
{
    PQfinish(conn);
    exit(1);
}

void
pg_free(void *ptr)
{
	if (ptr != NULL)
		free(ptr);
}


/*
 * Get destination directory.
 */
static DIR *
get_destination_dir(char *dest_folder)
{
	DIR		   *dir;

	//Assert(dest_folder != NULL);
	dir = opendir(dest_folder);
	if (dir == NULL)
	{
		//pg_log_error("could not open directory \"%s\": %m", basedir);
		pgmoneta_log_error("could not open directory \"%s\": %m", basedir);
		exit(1);
	}

	return dir;
}


/*
 * Close existing directory.
 */
static void
close_destination_dir(DIR *dest_dir, char *dest_folder)
{
	//Assert(dest_dir != NULL && dest_folder != NULL);
	if (closedir(dest_dir))
	{
		//pg_log_error("could not close directory \"%s\": %m", dest_folder);
		pgmoneta_log_error("could not close directory \"%s\": %m", dest_folder);
		exit(1);
	}
}



/*
 * This is the default value for wal_segment_size to be used when initdb is run
 * without the --wal-segsize option.  It must be a valid segment size.
 */
#define DEFAULT_XLOG_SEG_SIZE	(16*1024*1024)
#define PG_BINARY	0

#define XLogSegmentsPerXLogId(wal_segsz_bytes)	\
	(UINT64CONST(0x100000000) / (wal_segsz_bytes))


/* Length of XLog file name */
#define XLOG_FNAME_LEN	   24


/*
 * Generate a WAL segment file name.  Do not use this macro in a helper
 * function allocating the result generated.
 */
#define XLogFileName(fname, tli, logSegNo, wal_segsz_bytes)	\
	snprintf(fname, MAXFNAMELEN, "%08X%08X%08X", tli,		\
			 (uint32) ((logSegNo) / XLogSegmentsPerXLogId(wal_segsz_bytes)), \
			 (uint32) ((logSegNo) % XLogSegmentsPerXLogId(wal_segsz_bytes)))

#define XLogFileNameById(fname, tli, log, seg)	\
	snprintf(fname, MAXFNAMELEN, "%08X%08X%08X", tli, log, seg)

#define IsXLogFileName(fname) \
	(strlen(fname) == XLOG_FNAME_LEN && \
	 strspn(fname, "0123456789ABCDEF") == XLOG_FNAME_LEN)

/*
 * XLOG segment with .partial suffix.  Used by pg_receivewal and at end of
 * archive recovery, when we want to archive a WAL segment but it might not
 * be complete yet.
 */
#define IsPartialXLogFileName(fname)	\
	(strlen(fname) == XLOG_FNAME_LEN + strlen(".partial") &&	\
	 strspn(fname, "0123456789ABCDEF") == XLOG_FNAME_LEN &&		\
	 strcmp((fname) + XLOG_FNAME_LEN, ".partial") == 0)

#define XLogFromFileName(fname, tli, logSegNo, wal_segsz_bytes)	\
	do {												\
		uint32 log;										\
		uint32 seg;										\
		sscanf(fname, "%08X%08X%08X", tli, &log, &seg); \
		*logSegNo = (uint64) log * XLogSegmentsPerXLogId(wal_segsz_bytes) + seg; \
	} while (0)

#define XLogFilePath(path, tli, logSegNo, wal_segsz_bytes)	\
	snprintf(path, MAXPGPATH, XLOGDIR "/%08X%08X%08X", tli,	\
			 (uint32) ((logSegNo) / XLogSegmentsPerXLogId(wal_segsz_bytes)), \
			 (uint32) ((logSegNo) % XLogSegmentsPerXLogId(wal_segsz_bytes)))

#define TLHistoryFileName(fname, tli)	\
	snprintf(fname, MAXFNAMELEN, "%08X.history", tli)

#define IsTLHistoryFileName(fname)	\
	(strlen(fname) == 8 + strlen(".history") &&		\
	 strspn(fname, "0123456789ABCDEF") == 8 &&		\
	 strcmp((fname) + 8, ".history") == 0)

#define TLHistoryFilePath(path, tli)	\
	snprintf(path, MAXPGPATH, XLOGDIR "/%08X.history", tli)

#define StatusFilePath(path, xlog, suffix)	\
	snprintf(path, MAXPGPATH, XLOGDIR "/archive_status/%s%s", xlog, suffix)

#define BackupHistoryFileName(fname, tli, logSegNo, startpoint, wal_segsz_bytes) \
	snprintf(fname, MAXFNAMELEN, "%08X%08X%08X.%08X.backup", tli, \
			 (uint32) ((logSegNo) / XLogSegmentsPerXLogId(wal_segsz_bytes)), \
			 (uint32) ((logSegNo) % XLogSegmentsPerXLogId(wal_segsz_bytes)), \
			 (uint32) (XLogSegmentOffset(startpoint, wal_segsz_bytes)))

#define IsBackupHistoryFileName(fname) \
	(strlen(fname) > XLOG_FNAME_LEN && \
	 strspn(fname, "0123456789ABCDEF") == XLOG_FNAME_LEN && \
	 strcmp((fname) + strlen(fname) - strlen(".backup"), ".backup") == 0)

#define BackupHistoryFilePath(path, tli, logSegNo, startpoint, wal_segsz_bytes)	\
	snprintf(path, MAXPGPATH, XLOGDIR "/%08X%08X%08X.%08X.backup", tli, \
			 (uint32) ((logSegNo) / XLogSegmentsPerXLogId(wal_segsz_bytes)), \
			 (uint32) ((logSegNo) % XLogSegmentsPerXLogId(wal_segsz_bytes)), \
			 (uint32) (XLogSegmentOffset((startpoint), wal_segsz_bytes)))


#define XLogSegNoOffsetToRecPtr(segno, offset, wal_segsz_bytes, dest) \
		(dest) = (segno) * (wal_segsz_bytes) + (offset)



/*
 * Determine starting location for streaming, based on any existing xlog
 * segments in the directory. We start at the end of the last one that is
 * complete (size matches wal segment size), on the timeline with highest ID.
 *
 * If there are no WAL files in the directory, returns InvalidXLogRecPtr.
 */
static XLogRecPtr
FindStreamingStart(uint32 *tli)
{
//#ifdef findstart
	pgmoneta_log_info("find streaming start tli is: %s", tli);
	DIR		   *dir;
	struct dirent *dirent;
	XLogSegNo	high_segno = 0;
	uint32		high_tli = 0;
	bool		high_ispartial = false;

	dir = get_destination_dir(basedir);

	while (errno = 0, (dirent = readdir(dir)) != NULL)
	{
		uint32		tli;
		XLogSegNo	segno;
		bool		ispartial;
		bool		iscompress;

		/*
		 * Check if the filename looks like an xlog file, or a .partial file.
		 */
		if (IsXLogFileName(dirent->d_name))
		{
			ispartial = false;
			iscompress = false;
		}
		else if (IsPartialXLogFileName(dirent->d_name))
		{
			ispartial = true;
			iscompress = false;
		}
		//else if (IsCompressXLogFileName(dirent->d_name))
		//{
		//	ispartial = false;
		//	iscompress = true;
		//}
		//else if (IsPartialCompressXLogFileName(dirent->d_name))
		//{
		//	ispartial = true;
		//	iscompress = true;
		//}
		else
			continue;

		/*
		 * Looks like an xlog file. Parse its position.
		 */
		XLogFromFileName(dirent->d_name, &tli, &segno, WalSegSz); //give value to tli

		/*
		 * Check that the segment has the right size, if it's supposed to be
		 * completed.  For non-compressed segments just check the on-disk size
		 * and see if it matches a completed segment. For compressed segments,
		 * look at the last 4 bytes of the compressed file, which is where the
		 * uncompressed size is located for gz files with a size lower than
		 * 4GB, and then compare it to the size of a completed segment. The 4
		 * last bytes correspond to the ISIZE member according to
		 * http://www.zlib.org/rfc-gzip.html.
		 */
		if (!ispartial && !iscompress)
		{
			struct stat statbuf;
			char		fullpath[MAXPGPATH * 2];

			snprintf(fullpath, sizeof(fullpath), "%s/%s", basedir, dirent->d_name);
			if (stat(fullpath, &statbuf) != 0)
			{
				//pg_log_error("could not stat file \"%s\": %m", fullpath);
				pgmoneta_log_error("could not stat file \"%s\": %m", fullpath);
				exit(1);
			}

			if (statbuf.st_size != WalSegSz)
			{
				//pg_log_warning("segment file \"%s\" has incorrect size %lld, skipping",
				//			   dirent->d_name, (long long int) statbuf.st_size);
				pgmoneta_log_error("segment file \"%s\" has incorrect size %lld, skipping",
							   dirent->d_name, (long long int) statbuf.st_size);
				continue;
			}
		}
		else if (!ispartial && iscompress)
		{
			int			fd;
			char		buf[4];
			int			bytes_out;
			char		fullpath[MAXPGPATH * 2];
			int			r;

			snprintf(fullpath, sizeof(fullpath), "%s/%s", basedir, dirent->d_name);

			fd = open(fullpath, O_RDONLY | PG_BINARY, 0);
			if (fd < 0)
			{
				//pg_log_error("could not open compressed file \"%s\": %m",
				//			 fullpath);
				pgmoneta_log_error("could not open compressed file \"%s\": %m",
							 fullpath);
				exit(1);
			}
			if (lseek(fd, (off_t) (-4), SEEK_END) < 0)
			{
				//pg_log_error("could not seek in compressed file \"%s\": %m",
				//			 fullpath);
				pgmoneta_log_error("could not seek in compressed file \"%s\": %m",
							 fullpath);
				exit(1);
			}
			r = read(fd, (char *) buf, sizeof(buf));
			if (r != sizeof(buf))
			{
				if (r < 0)
					//pg_log_error("could not read compressed file \"%s\": %m",
					//			 fullpath);
					pgmoneta_log_error("could not read compressed file \"%s\": %m",
								 fullpath);
				else
					//pg_log_error("could not read compressed file \"%s\": read %d of %zu",
					//			 fullpath, r, sizeof(buf));
					pgmoneta_log_error("could not read compressed file \"%s\": read %d of %zu",
								 fullpath, r, sizeof(buf));
				exit(1);
			}

			close(fd);
			bytes_out = (buf[3] << 24) | (buf[2] << 16) |
				(buf[1] << 8) | buf[0];

			if (bytes_out != WalSegSz)
			{
				//pg_log_warning("compressed segment file \"%s\" has incorrect uncompressed size %d, skipping",
				//			   dirent->d_name, bytes_out);
				pgmoneta_log_error("compressed segment file \"%s\" has incorrect uncompressed size %d, skipping",
							   dirent->d_name, bytes_out);
				continue;
			}
		}

		/* Looks like a valid segment. Remember that we saw it. */
		if ((segno > high_segno) ||
			(segno == high_segno && tli > high_tli) ||
			(segno == high_segno && tli == high_tli && high_ispartial && !ispartial))
		{
			high_segno = segno;
			high_tli = tli;
			high_ispartial = ispartial;
		}
	}

	if (errno)
	{
		//pg_log_error("could not read directory \"%s\": %m", basedir);
		pgmoneta_log_error("could not read directory \"%s\": %m", basedir);
		exit(1);
	}

	close_destination_dir(dir, basedir);

	if (high_segno > 0)
	{
		XLogRecPtr	high_ptr;

		/*
		 * Move the starting pointer to the start of the next segment, if the
		 * highest one we saw was completed. Otherwise start streaming from
		 * the beginning of the .partial segment.
		 */
		if (!high_ispartial)
			high_segno++;

		XLogSegNoOffsetToRecPtr(high_segno, 0, WalSegSz, high_ptr);

		*tli = high_tli;
		return high_ptr;
	}
	else
//#endif
		return InvalidXLogRecPtr;
}

static bool
stop_streaming(XLogRecPtr xlogpos, uint32 timeline, bool segment_finished)
{
	static uint32 prevtimeline = 0;
	static XLogRecPtr prevpos = InvalidXLogRecPtr;

#ifdef verbose_
	/* we assume that we get called once at the end of each segment */
	if (verbose && segment_finished)
		pg_log_info("finished segment at %X/%X (timeline %u)",
					LSN_FORMAT_ARGS(xlogpos),
					timeline);
#endif
	if (!XLogRecPtrIsInvalid(endpos) && endpos < xlogpos)
	{
#ifdef verbose_
		if (verbose)
			pg_log_info("stopped log streaming at %X/%X (timeline %u)",
						LSN_FORMAT_ARGS(xlogpos),
						timeline);
#endif
		time_to_stop = true;
		return true;
	}

	/*
	 * Note that we report the previous, not current, position here. After a
	 * timeline switch, xlogpos points to the beginning of the segment because
	 * that's where we always begin streaming. Reporting the end of previous
	 * timeline isn't totally accurate, because the next timeline can begin
	 * slightly before the end of the WAL that we received on the previous
	 * timeline, but it's close enough for reporting purposes.
	 */
#ifdef verbose_
	if (verbose && prevtimeline != 0 && prevtimeline != timeline)
		pg_log_info("switched to timeline %u at %X/%X",
					timeline,
					LSN_FORMAT_ARGS(prevpos));
#endif
	prevtimeline = timeline;
	prevpos = xlogpos;

	if (time_to_stop)
	{
#ifdef verbose_
		if (verbose)
			pg_log_info("received interrupt signal, exiting");
#endif
		return true;
	}
	return false;
}

static bool
mark_file_as_archived(StreamCtl *stream, const char *fname)
{
	Walfile    *f;
	static char tmppath[MAXPGPATH];

	snprintf(tmppath, sizeof(tmppath), "archive_status/%s.done",
			 fname);

	f = stream->walmethod->open_for_write(tmppath, NULL, 0);
	if (f == NULL)
	{
		//pg_log_error("could not create archive status file \"%s\": %s",
		//			 tmppath, stream->walmethod->getlasterror());
		pgmoneta_log_error("could not create archive status file \"%s\": %s",
					 tmppath, stream->walmethod->getlasterror());
		return false;
	}

	if (stream->walmethod->close(f, CLOSE_NORMAL) != 0)
	{
		//pg_log_error("could not close archive status file \"%s\": %s",
		//			 tmppath, stream->walmethod->getlasterror());
		pgmoneta_log_error("could not close archive status file \"%s\": %s",
					 tmppath, stream->walmethod->getlasterror());
		return false;
	}

	return true;
}

/*
 * Close the current WAL file (if open), and rename it to the correct
 * filename if it's complete. On failure, prints an error message to stderr
 * and returns false, otherwise returns true.
 */
static bool
close_walfile(StreamCtl *stream, XLogRecPtr pos)
{
//#ifdef close_wal
	off_t		currpos;
	int			r;

	if (walfile == NULL)
		return true;

	currpos = stream->walmethod->get_current_pos(walfile);
	if (currpos == -1)
	{
		//pg_log_error("could not determine seek position in file \"%s\": %s",
		//			 current_walfile_name, stream->walmethod->getlasterror());
        pgmoneta_log_error("could not determine seek position in file \"%s\": %s",
					 current_walfile_name, stream->walmethod->getlasterror());
		stream->walmethod->close(walfile, CLOSE_UNLINK);
		walfile = NULL;

		return false;
	}

	if (stream->partial_suffix)
	{
		if (currpos == WalSegSz)
			r = stream->walmethod->close(walfile, CLOSE_NORMAL);
		else
		{
			//pg_log_info("not renaming \"%s%s\", segment is not complete",
			//			current_walfile_name, stream->partial_suffix);
            pgmoneta_log_info("not renaming \"%s%s\", segment is not complete",
						current_walfile_name, stream->partial_suffix);
			r = stream->walmethod->close(walfile, CLOSE_NO_RENAME);
		}
	}
	else
		r = stream->walmethod->close(walfile, CLOSE_NORMAL);

	walfile = NULL;

	if (r != 0)
	{
		//pg_log_error("could not close file \"%s\": %s",
		//			 current_walfile_name, stream->walmethod->getlasterror());
        pgmoneta_log_error("could not close file \"%s\": %s",
					 current_walfile_name, stream->walmethod->getlasterror());
		return false;
	}

	/*
	 * Mark file as archived if requested by the caller - pg_basebackup needs
	 * to do so as files can otherwise get archived again after promotion of a
	 * new node. This is in line with walreceiver.c always doing a
	 * XLogArchiveForceDone() after a complete segment.
	 */
	if (currpos == WalSegSz && stream->mark_done)
	{
		/* writes error message if failed */
		if (!mark_file_as_archived(stream, current_walfile_name))
			return false;
	}

	lastFlushPosition = pos;
//#endif
	return true;
}

/*
 * Check if we should continue streaming, or abort at this point.
 */
static bool
CheckCopyStreamStop(PGconn *conn, StreamCtl *stream, XLogRecPtr blockpos)
{
	if (still_sending && stream->stream_stop(blockpos, stream->timeline, false))
	{
		if (!close_walfile(stream, blockpos))
		{
			/* Potential error message is written by close_walfile */
			return false;
		}
		if (PQputCopyEnd(conn, NULL) <= 0 || PQflush(conn))
		{
			//pg_log_error("could not send copy-end packet: %s",
			//			 PQerrorMessage(conn));
            pgmoneta_log_error("could not send copy-end packet: %s",
						 PQerrorMessage(conn));
			return false;
		}
		still_sending = false;
	}

	return true;
}

/*
 * Converts an int64 to network byte order.
 */
void
fe_sendint64(int64 i, char *buf)
{
	//uint64		n64 = pg_hton64(i);

	//memcpy(buf, &n64, sizeof(n64));
    memcpy(buf, &i, sizeof(i));
}

/*
 * Send a Standby Status Update message to server.
 */
static bool
sendFeedback(PGconn *conn, XLogRecPtr blockpos, TimestampTz now, bool replyRequested)
{
	char		replybuf[1 + 8 + 8 + 8 + 8 + 1];
	int			len = 0;

	replybuf[len] = 'r';
	len += 1;
	fe_sendint64(blockpos, &replybuf[len]); /* write */
	len += 8;
	if (reportFlushPosition)
		fe_sendint64(lastFlushPosition, &replybuf[len]);	/* flush */
	else
		fe_sendint64(InvalidXLogRecPtr, &replybuf[len]);	/* flush */
	len += 8;
	fe_sendint64(InvalidXLogRecPtr, &replybuf[len]);	/* apply */
	len += 8;
	fe_sendint64(now, &replybuf[len]);	/* sendTime */
	len += 8;
	replybuf[len] = replyRequested ? 1 : 0; /* replyRequested */
	len += 1;

	if (PQputCopyData(conn, replybuf, len) <= 0 || PQflush(conn))
	{
		//pg_log_error("could not send feedback packet: %s",
		//			 PQerrorMessage(conn));
        pgmoneta_log_error("could not send feedback packet: %s",
					 PQerrorMessage(conn));
		return false;
	}

	return true;
}

/*
 * Frontend version of TimestampDifferenceExceeds(), since we are not
 * linked with backend code.
 */
bool
feTimestampDifferenceExceeds(TimestampTz start_time,
							 TimestampTz stop_time,
							 int msec)
{
	TimestampTz diff = stop_time - start_time;

	return (diff >= msec * INT64CONST(1000));
}

/*
 * Frontend version of TimestampDifference(), since we are not linked with
 * backend code.
 */
void
feTimestampDifference(TimestampTz start_time, TimestampTz stop_time,
					  long *secs, int *microsecs)
{
	TimestampTz diff = stop_time - start_time;

	if (diff <= 0)
	{
		*secs = 0;
		*microsecs = 0;
	}
	else
	{
		*secs = (long) (diff / USECS_PER_SEC);
		*microsecs = (int) (diff % USECS_PER_SEC);
	}
}

/*
 * Calculate how long send/receive loops should sleep
 */
static long
CalculateCopyStreamSleeptime(TimestampTz now, int standby_message_timeout,
							 TimestampTz last_status)
{
	TimestampTz status_targettime = 0;
	long		sleeptime;

	if (standby_message_timeout && still_sending)
		status_targettime = last_status +
			(standby_message_timeout - 1) * ((int64) 1000);

	if (status_targettime > 0)
	{
		long		secs;
		int			usecs;

		feTimestampDifference(now,
							  status_targettime,
							  &secs,
							  &usecs);
		/* Always sleep at least 1 sec */
		if (secs <= 0)
		{
			secs = 1;
			usecs = 0;
		}

		sleeptime = secs * 1000 + usecs / 1000;
	}
	else
		sleeptime = -1;

	return sleeptime;
}

/*
 * Max
 *		Return the maximum of two numbers.
 */
#define Max(x, y)		((x) > (y) ? (x) : (y))

/*
 * Wait until we can read a CopyData message,
 * or timeout, or occurrence of a signal or input on the stop_socket.
 * (timeout_ms < 0 means wait indefinitely; 0 means don't wait.)
 *
 * Returns 1 if data has become available for reading, 0 if timed out
 * or interrupted by signal or stop_socket input, and -1 on an error.
 */
static int
CopyStreamPoll(PGconn *conn, long timeout_ms, pgsocket stop_socket)
{
	int			ret;
	fd_set		input_mask;
	int			connsocket;
	int			maxfd;
	struct timeval timeout;
	struct timeval *timeoutptr;

	connsocket = PQsocket(conn);
	if (connsocket < 0)
	{
		//pg_log_error("invalid socket: %s", PQerrorMessage(conn));
        pgmoneta_log_error("invalid socket: %s", PQerrorMessage(conn));
		return -1;
	}

	FD_ZERO(&input_mask);
	FD_SET(connsocket, &input_mask);
	maxfd = connsocket;
	if (stop_socket != PGINVALID_SOCKET)
	{
		FD_SET(stop_socket, &input_mask);
		maxfd = Max(maxfd, stop_socket);
	}

	if (timeout_ms < 0)
		timeoutptr = NULL;
	else
	{
		timeout.tv_sec = timeout_ms / 1000L;
		timeout.tv_usec = (timeout_ms % 1000L) * 1000L;
		timeoutptr = &timeout;
	}

	ret = select(maxfd + 1, &input_mask, NULL, NULL, timeoutptr);

	if (ret < 0)
	{
		//if (errno == EINTR)
		//	return 0;			/* Got a signal, so not an error */
		//pg_log_error("%s() failed: %m", "select");
        pgmoneta_log_error("%s() failed: %m", "select");
		return -1;
	}
	if (ret > 0 && FD_ISSET(connsocket, &input_mask))
		return 1;				/* Got input on connection socket */

	return 0;					/* Got timeout or input on stop_socket */
}

/*
 * Receive CopyData message available from XLOG stream, blocking for
 * maximum of 'timeout' ms.
 *
 * If data was received, returns the length of the data. *buffer is set to
 * point to a buffer holding the received message. The buffer is only valid
 * until the next CopyStreamReceive call.
 *
 * Returns 0 if no data was available within timeout, or if wait was
 * interrupted by signal or stop_socket input.
 * -1 on error. -2 if the server ended the COPY.
 */
static int
CopyStreamReceive(PGconn *conn, long timeout, pgsocket stop_socket,
				  char **buffer)
{
	char	   *copybuf = NULL;
	int			rawlen;

	if (*buffer != NULL)
		PQfreemem(*buffer);
	*buffer = NULL;

	/* Try to receive a CopyData message */
	rawlen = PQgetCopyData(conn, &copybuf, 1);
	if (rawlen == 0)
	{
		int			ret;

		/*
		 * No data available.  Wait for some to appear, but not longer than
		 * the specified timeout, so that we can ping the server.  Also stop
		 * waiting if input appears on stop_socket.
		 */
		ret = CopyStreamPoll(conn, timeout, stop_socket);
		if (ret <= 0)
			return ret;

		/* Now there is actually data on the socket */
		if (PQconsumeInput(conn) == 0)
		{
			//pg_log_error("could not receive data from WAL stream: %s",
			//			 PQerrorMessage(conn));
            pgmoneta_log_error("could not receive data from WAL stream: %s",
						 PQerrorMessage(conn));
			return -1;
		}

		/* Now that we've consumed some input, try again */
		rawlen = PQgetCopyData(conn, &copybuf, 1);
		if (rawlen == 0)
			return 0;
	}
	if (rawlen == -1)			/* end-of-streaming or error */
		return -2;
	if (rawlen == -2)
	{
		//pg_log_error("could not read COPY data: %s", PQerrorMessage(conn));
        pgmoneta_log_error("could not read COPY data: %s", PQerrorMessage(conn));
		return -1;
	}

	/* Return received messages to caller */
	*buffer = copybuf;
	return rawlen;
}

/* Julian-date equivalents of Day 0 in Unix and Postgres reckoning */
#define UNIX_EPOCH_JDATE		2440588 /* == date2j(1970, 1, 1) */
#define POSTGRES_EPOCH_JDATE	2451545 /* == date2j(2000, 1, 1) */

/*
 *	This doesn't adjust for uneven daylight savings time intervals or leap
 *	seconds, and it crudely estimates leap years.  A more accurate value
 *	for days per years is 365.2422.
 */
#define SECS_PER_YEAR	(36525 * 864)	/* avoid floating-point computation */
#define SECS_PER_DAY	86400
#define SECS_PER_HOUR	3600
#define SECS_PER_MINUTE 60
#define MINS_PER_HOUR	60

#define USECS_PER_DAY	INT64CONST(86400000000)
#define USECS_PER_HOUR	INT64CONST(3600000000)
#define USECS_PER_MINUTE INT64CONST(60000000)
#define USECS_PER_SEC	INT64CONST(1000000)
/*
 * Frontend version of GetCurrentTimestamp(), since we are not linked with
 * backend code.
 */
TimestampTz
feGetCurrentTimestamp(void)
{
	TimestampTz result;
	struct timeval tp;

	gettimeofday(&tp, NULL);

	result = (TimestampTz) tp.tv_sec -
		((POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE) * SECS_PER_DAY);
	result = (result * USECS_PER_SEC) + tp.tv_usec;

	return result;
}

/*
 * Process the keepalive message.
 */
static bool
ProcessKeepaliveMsg(PGconn *conn, StreamCtl *stream, char *copybuf, int len,
					XLogRecPtr blockpos, TimestampTz *last_status)
{
	int			pos;
	bool		replyRequested;
	TimestampTz now;

	/*
	 * Parse the keepalive message, enclosed in the CopyData message. We just
	 * check if the server requested a reply, and ignore the rest.
	 */
	pos = 1;					/* skip msgtype 'k' */
	pos += 8;					/* skip walEnd */
	pos += 8;					/* skip sendTime */

	if (len < pos + 1)
	{
		//pg_log_error("streaming header too small: %d", len);
        pgmoneta_log_error("streaming header too small: %d", len);
		return false;
	}
	replyRequested = copybuf[pos];

	/* If the server requested an immediate reply, send one. */
	if (replyRequested && still_sending)
	{
		if (reportFlushPosition && lastFlushPosition < blockpos &&
			walfile != NULL)
		{
			/*
			 * If a valid flush location needs to be reported, flush the
			 * current WAL file so that the latest flush location is sent back
			 * to the server. This is necessary to see whether the last WAL
			 * data has been successfully replicated or not, at the normal
			 * shutdown of the server.
			 */
			if (stream->walmethod->sync(walfile) != 0)
			{
				//pg_log_fatal("could not fsync file \"%s\": %s",
							 //current_walfile_name, stream->walmethod->getlasterror());
                pgmoneta_log_error("could not fsync file \"%s\": %s",
							 current_walfile_name, stream->walmethod->getlasterror());
				exit(1);
			}
			lastFlushPosition = blockpos;
		}

		now = feGetCurrentTimestamp();
		if (!sendFeedback(conn, blockpos, now, false))
			return false;
		*last_status = now;
	}

	return true;
}


/*
 * Handle end of the copy stream.
 */
static PGresult *
HandleEndOfCopyStream(PGconn *conn, StreamCtl *stream, char *copybuf,
					  XLogRecPtr blockpos, XLogRecPtr *stoppos)
{
	PGresult   *res = PQgetResult(conn);

	/*
	 * The server closed its end of the copy stream.  If we haven't closed
	 * ours already, we need to do so now, unless the server threw an error,
	 * in which case we don't.
	 */
	if (still_sending)
	{
		if (!close_walfile(stream, blockpos))
		{
			/* Error message written in close_walfile() */
			PQclear(res);
			return NULL;
		}
		if (PQresultStatus(res) == PGRES_COPY_IN)
		{
			if (PQputCopyEnd(conn, NULL) <= 0 || PQflush(conn))
			{
				//pg_log_error("could not send copy-end packet: %s",
				//			 PQerrorMessage(conn));
                pgmoneta_log_error("could not send copy-end packet: %s",
							 PQerrorMessage(conn));
				PQclear(res);
				return NULL;
			}
			res = PQgetResult(conn);
		}
		still_sending = false;
	}
	if (copybuf != NULL)
		PQfreemem(copybuf);
	*stoppos = blockpos;
	return res;
}

static inline uint64
pg_bswap64(uint64 x)
{
	return
		((x << 56) & UINT64CONST(0xff00000000000000)) |
		((x << 40) & UINT64CONST(0x00ff000000000000)) |
		((x << 24) & UINT64CONST(0x0000ff0000000000)) |
		((x << 8) & UINT64CONST(0x000000ff00000000)) |
		((x >> 8) & UINT64CONST(0x00000000ff000000)) |
		((x >> 24) & UINT64CONST(0x0000000000ff0000)) |
		((x >> 40) & UINT64CONST(0x000000000000ff00)) |
		((x >> 56) & UINT64CONST(0x00000000000000ff));
}

/*
 * Converts an int64 from network byte order to native format.
 */
int64
fe_recvint64(char *buf)
{
	uint64		n64;

	memcpy(&n64, buf, sizeof(n64));

	return pg_bswap64(n64);
}

/*
 * Compute a segment number from an XLogRecPtr.
 *
 * For XLByteToSeg, do the computation at face value.  For XLByteToPrevSeg,
 * a boundary byte is taken to be in the previous segment.  This is suitable
 * for deciding which segment to write given a pointer to a record end,
 * for example.
 */
#define XLByteToSeg(xlrp, logSegNo, wal_segsz_bytes) \
	logSegNo = (xlrp) / (wal_segsz_bytes)

#define XLByteToPrevSeg(xlrp, logSegNo, wal_segsz_bytes) \
	logSegNo = ((xlrp) - 1) / (wal_segsz_bytes)

/*
 * These macros encapsulate knowledge about the exact layout of XLog file
 * names, timeline history file names, and archive-status file names.
 */
#define MAXFNAMELEN		64

/* check that the given size is a valid wal_segment_size */
#define IsPowerOf2(x) (x > 0 && ((x) & ((x)-1)) == 0)
#define IsValidWalSegSize(size) \
	 (IsPowerOf2(size) && \
	 ((size) >= WalSegMinSize && (size) <= WalSegMaxSize))

#define XLogSegmentsPerXLogId(wal_segsz_bytes)	\
	(UINT64CONST(0x100000000) / (wal_segsz_bytes))

#define XLogSegNoOffsetToRecPtr(segno, offset, wal_segsz_bytes, dest) \
		(dest) = (segno) * (wal_segsz_bytes) + (offset)

#define XLogSegmentOffset(xlogptr, wal_segsz_bytes)	\
	((xlogptr) & ((wal_segsz_bytes) - 1))

/*
 * Generate a WAL segment file name.  Do not use this macro in a helper
 * function allocating the result generated.
 */
#define XLogFileName(fname, tli, logSegNo, wal_segsz_bytes)	\
	snprintf(fname, MAXFNAMELEN, "%08X%08X%08X", tli,		\
			 (uint32) ((logSegNo) / XLogSegmentsPerXLogId(wal_segsz_bytes)), \
			 (uint32) ((logSegNo) % XLogSegmentsPerXLogId(wal_segsz_bytes)))

#define XLogFileNameById(fname, tli, log, seg)	\
	snprintf(fname, MAXFNAMELEN, "%08X%08X%08X", tli, log, seg)
/*
#define IsXLogFileName(fname) \
	(strlen(fname) == XLOG_FNAME_LEN && \
	 strspn(fname, "0123456789ABCDEF") == XLOG_FNAME_LEN)
*/
/*
 * Open a new WAL file in the specified directory.
 *
 * Returns true if OK; on failure, returns false after printing an error msg.
 * On success, 'walfile' is set to the FD for the file, and the base filename
 * (without partial_suffix) is stored in 'current_walfile_name'.
 *
 * The file will be padded to 16Mb with zeroes.
 */
static bool
open_walfile(StreamCtl *stream, XLogRecPtr startpoint)
{
	Walfile    *f;
	char	   *fn;
	ssize_t		size;
	XLogSegNo	segno;

    pgmoneta_log_info("konglx: open_walfile begin to execute");
	XLByteToSeg(startpoint, segno, WalSegSz);
	XLogFileName(current_walfile_name, stream->timeline, segno, WalSegSz);

	/* Note that this considers the compression used if necessary */
	fn = stream->walmethod->get_file_name(current_walfile_name,
										  stream->partial_suffix);
    pgmoneta_log_info("konglx: stream->walmethod->get_file_name is over");
	/*
	 * When streaming to files, if an existing file exists we verify that it's
	 * either empty (just created), or a complete WalSegSz segment (in which
	 * case it has been created and padded). Anything else indicates a corrupt
	 * file. Compressed files have no need for padding, so just ignore this
	 * case.
	 *
	 * When streaming to tar, no file with this name will exist before, so we
	 * never have to verify a size.
	 */
    pgmoneta_log_info("ready to test exist");
    //konglx change here
	//if (stream->walmethod->compression() == 0 &&
    if (0 == 0 &&
		stream->walmethod->existsfile(fn))
	{
        pgmoneta_log_info("stream->walmethod->compression() == 0 && stream->walmethod->existsfile(fn)");
		size = stream->walmethod->get_file_size(fn);
		if (size < 0)
		{
			//pg_log_error("could not get size of write-ahead log file \"%s\": %s",
			//			 fn, stream->walmethod->getlasterror());
            pgmoneta_log_error("could not get size of write-ahead log file \"%s\": %s",
						 fn, stream->walmethod->getlasterror());
			pg_free(fn);
			return false;
		}
		if (size == WalSegSz)
		{
            pgmoneta_log_info("konglx: Already padded file. Open it for use");
			/* Already padded file. Open it for use */
			f = stream->walmethod->open_for_write(current_walfile_name, stream->partial_suffix, 0);
			if (f == NULL)
			{
				//pg_log_error("could not open existing write-ahead log file \"%s\": %s",
				//			 fn, stream->walmethod->getlasterror());
                pgmoneta_log_error("could not open existing write-ahead log file \"%s\": %s",
							 fn, stream->walmethod->getlasterror());
				pg_free(fn);
				return false;
			}

            pgmoneta_log_info("konglx: stream->walmethod->sync(f) ready to exec");
			/* fsync file in case of a previous crash */
			if (stream->walmethod->sync(f) != 0)
			{
				//pg_log_fatal("could not fsync existing write-ahead log file \"%s\": %s",
				//			 fn, stream->walmethod->getlasterror());
                pgmoneta_log_fatal("could not fsync existing write-ahead log file \"%s\": %s",
							 fn, stream->walmethod->getlasterror());
				stream->walmethod->close(f, CLOSE_UNLINK);
				exit(1);
			}

			walfile = f;
			pg_free(fn);
			return true;
		}
		if (size != 0)
		{
			/* if write didn't set errno, assume problem is no disk space */
			/*if (errno == 0)
			//	errno = ENOSPC;
			pg_log_error(ngettext("write-ahead log file \"%s\" has %d byte, should be 0 or %d",
								  "write-ahead log file \"%s\" has %d bytes, should be 0 or %d",
								  size),
						 fn, (int) size, WalSegSz);
                         */
            pgmoneta_log_error(ngettext("write-ahead log file \"%s\" has %d byte, should be 0 or %d",
								  "write-ahead log file \"%s\" has %d bytes, should be 0 or %d",
								  size),
						 fn, (int) size, WalSegSz);
			pg_free(fn);
			return false;
		}
		/* File existed and was empty, so fall through and open */
	}

	/* No file existed, so create one */
    pgmoneta_log_info("konglx: stream->walmethod->open_for_write");
	f = stream->walmethod->open_for_write(current_walfile_name,
										  stream->partial_suffix, WalSegSz);
	if (f == NULL)
	{
		//pg_log_error("could not open write-ahead log file \"%s\": %s",
		//			 fn, stream->walmethod->getlasterror());
        pgmoneta_log_error("could not open write-ahead log file \"%s\": %s",
					 fn, stream->walmethod->getlasterror());
		pg_free(fn);
		return false;
	}

	pg_free(fn);
	walfile = f;
	return true;
}


/*
 * Process XLogData message.
 */
static bool
ProcessXLogDataMsg(PGconn *conn, StreamCtl *stream, char *copybuf, int len,
				   XLogRecPtr *blockpos)
{
	int			xlogoff;
	int			bytes_left;
	int			bytes_written;
	int			hdr_len;

	/*
	 * Once we've decided we don't want to receive any more, just ignore any
	 * subsequent XLogData messages.
	 */
	if (!(still_sending))
		return true;

	/*
	 * Read the header of the XLogData message, enclosed in the CopyData
	 * message. We only need the WAL location field (dataStart), the rest of
	 * the header is ignored.
	 */
	hdr_len = 1;				/* msgtype 'w' */
	hdr_len += 8;				/* dataStart */
	hdr_len += 8;				/* walEnd */
	hdr_len += 8;				/* sendTime */
	if (len < hdr_len)
	{
		//pg_log_error("streaming header too small: %d", len);
        pgmoneta_log_error("streaming header too small: %d", len);
		return false;
	}
	*blockpos = fe_recvint64(&copybuf[1]);

	pgmoneta_log_info("konglx:*blockpos = fe_recvint64(&copybuf[1]);  %d",*blockpos);

	/* Extract WAL location for this block */
	xlogoff = XLogSegmentOffset(*blockpos, WalSegSz);
	pgmoneta_log_info("WalSegSz: WalSegSz backup_wal.c 1075 %d",WalSegSz);
	/*
	 * Verify that the initial location in the stream matches where we think
	 * we are.
	 */
	if (walfile == NULL)
	{
        pgmoneta_log_info("konglx:walfile == NULL");
		/* No file open yet */
		if (xlogoff != 0)
		{
			//pg_log_error("received write-ahead log record for offset %u with no file open",
			//			 xlogoff);
            pgmoneta_log_info("received write-ahead log record for offset %u with no file open",
						 xlogoff);
			return false;
		}
	}
	else
	{
        pgmoneta_log_info("konglx:walfile != NULL");
		/* More data in existing segment */
		if (stream->walmethod->get_current_pos(walfile) != xlogoff)
		{
			//pg_log_error("got WAL data offset %08x, expected %08x",
			//			 xlogoff, (int) stream->walmethod->get_current_pos(walfile));
            pgmoneta_log_error("got WAL data offset %08x, expected %08x",
						 xlogoff, (int) stream->walmethod->get_current_pos(walfile));
			return false;
		}
	}

	bytes_left = len - hdr_len;
	bytes_written = 0;

    pgmoneta_log_info("konglx: bytes_left %d",bytes_left);

	pgmoneta_log_info("konglx: brefore while (bytes_left)");

	while (bytes_left)
	{
		int			bytes_to_write;
		pgmoneta_log_info("konglx: start loop bytes_left %d",bytes_left);
		/*
		 * If crossing a WAL boundary, only write up until we reach wal
		 * segment size.
		 */
		if (xlogoff + bytes_left > WalSegSz)
			bytes_to_write = WalSegSz - xlogoff;
		else
			bytes_to_write = bytes_left;
		pgmoneta_log_info("konglx: bytes_to_write: %d",bytes_to_write);
        pgmoneta_log_info("konglx: open_walfile ");
		if (walfile == NULL)
		{
            pgmoneta_log_info("konglx: walfile == NULL");
			if (!open_walfile(stream, *blockpos))
			{
				/* Error logged by open_walfile */
                pgmoneta_log_error("!open_walfile(stream, *blockpos)");
				return false;
			}
		}
        pgmoneta_log_info("konglx:stream->walmethod->write begin write!");
		if (stream->walmethod->write(walfile, copybuf + hdr_len + bytes_written,
									 bytes_to_write) != bytes_to_write)
		{
			/*pg_log_error("could not write %u bytes to WAL file \"%s\": %s",
						 bytes_to_write, current_walfile_name,
						 stream->walmethod->getlasterror());
            */
           pgmoneta_log_error("could not write %u bytes to WAL file \"%s\": %s",
						 bytes_to_write, current_walfile_name,
						 stream->walmethod->getlasterror());
			return false;
		}

		/* Write was successful, advance our position */
		bytes_written += bytes_to_write;
		bytes_left -= bytes_to_write;
		*blockpos += bytes_to_write;
		xlogoff += bytes_to_write;

        pgmoneta_log_info("konglx: Write was successful, advance our position");
		/* Did we reach the end of a WAL segment? */
		if (XLogSegmentOffset(*blockpos, WalSegSz) == 0)
		{
			pgmoneta_log_info("konglx: start XLogSegmentOffset(*blockpos, WalSegSz) == 0");
			if (!close_walfile(stream, *blockpos)) {
				/* Error message written in close_walfile() */
				pgmoneta_log_info("konglx: brefore return !close_walfile(stream, *blockpos)");
				return false;
			}
			pgmoneta_log_info("konglx: xlogoff = 0;");
			
			xlogoff = 0;

			if (still_sending && stream->stream_stop(*blockpos, stream->timeline, true))
			{
				pgmoneta_log_info("konglx: still_sending && stream->stream_stop is true");
				if (PQputCopyEnd(conn, NULL) <= 0 || PQflush(conn))
				{
					//pg_log_error("could not send copy-end packet: %s",
					//			 PQerrorMessage(conn));
                    pgmoneta_log_error("could not send copy-end packet: %s",
								 PQerrorMessage(conn));
					return false;
				}
				still_sending = false;
				pgmoneta_log_info("before return if still_sending && stream->stream_stop");
				return true;	/* ignore the rest of this XLogData packet */
			}
		}

		pgmoneta_log_info("konglx: end loop bytes_left %d",bytes_left);
	}
	/* No more data left to write, receive next copy packet */

	return true;
}


/*
 * The main loop of ReceiveXlogStream. Handles the COPY stream after
 * initiating streaming with the START_REPLICATION command.
 *
 * If the COPY ends (not necessarily successfully) due a message from the
 * server, returns a PGresult and sets *stoppos to the last byte written.
 * On any other sort of error, returns NULL.
 */
static PGresult *
HandleCopyStream(PGconn *conn, StreamCtl *stream,
				 XLogRecPtr *stoppos)
{
	char	   *copybuf = NULL;
	TimestampTz last_status = -1;
	XLogRecPtr	blockpos = stream->startpos;
	pgmoneta_log_info("konglx: begin: HandleCopyStream: %d",stream->startpos);
	still_sending = true;

	while (1)
	{
		int			r;
		TimestampTz now;
		long		sleeptime;

		/*
		 * Check if we should continue streaming, or abort at this point.
		 */
		if (!CheckCopyStreamStop(conn, stream, blockpos))
			goto error;

		now = feGetCurrentTimestamp();

		/*
		 * If synchronous option is true, issue sync command as soon as there
		 * are WAL data which has not been flushed yet.
		 */
		if (stream->synchronous && lastFlushPosition < blockpos && walfile != NULL)
		{
			if (stream->walmethod->sync(walfile) != 0)
			{
				//pg_log_fatal("could not fsync file \"%s\": %s",
				//			 current_walfile_name, stream->walmethod->getlasterror());
                pgmoneta_log_error("could not fsync file \"%s\": %s",
							 current_walfile_name, stream->walmethod->getlasterror());
				exit(1);
			}
			lastFlushPosition = blockpos;

			/*
			 * Send feedback so that the server sees the latest WAL locations
			 * immediately.
			 */
			pgmoneta_log_info("konglx: begin: HandleCopyStream: blockpos: %d",blockpos);
			if (!sendFeedback(conn, blockpos, now, false))
				goto error;
			last_status = now;
		}

		/*
		 * Potentially send a status message to the primary
		 */
		if (still_sending && stream->standby_message_timeout > 0 &&
			feTimestampDifferenceExceeds(last_status, now,
										 stream->standby_message_timeout))
		{
			pgmoneta_log_info("konglx: begin: HandleCopyStream: blockpos22: %d",blockpos);
			/* Time to send feedback! */
			if (!sendFeedback(conn, blockpos, now, false))
				goto error;
			last_status = now;
		}

		/*
		 * Calculate how long send/receive loops should sleep
		 */
		sleeptime = CalculateCopyStreamSleeptime(now, stream->standby_message_timeout,
												 last_status);

		pgmoneta_log_info("konglx: sleeptime = CalculateCopyStreamSleeptime: %d ", sleeptime);

		r = CopyStreamReceive(conn, sleeptime, stream->stop_socket, &copybuf);
		pgmoneta_log_info("konglx: r = CopyStreamReceive %d",r);
		// each  loop per packet 
		while (r != 0)
		{
			if (r == -1)
				goto error;
			if (r == -2)
			{
				PGresult   *res = HandleEndOfCopyStream(conn, stream, copybuf, blockpos, stoppos);

				if (res == NULL)
					goto error;
				else
					return res;
			}

			/* Check the message type. */
			if (copybuf[0] == 'k')
			{
                pgmoneta_log_info("copybuf[0] == 'k'");
				if (!ProcessKeepaliveMsg(conn, stream, copybuf, r, blockpos,
										 &last_status))
					goto error;
			}
			else if (copybuf[0] == 'w')
			{
                pgmoneta_log_info("copybuf[0] == 'w'");

				pgmoneta_log_info("konglx: before ProcessXLogDataMsg test copybuf[1]  %d",copybuf[1]);

				if (!ProcessXLogDataMsg(conn, stream, copybuf, r, &blockpos))
					goto error;
                
				/*
				 * Check if we should continue streaming, or abort at this
				 * point.
				 */
				if (!CheckCopyStreamStop(conn, stream, blockpos))
					goto error;
			}
			else
			{
				//pg_log_error("unrecognized streaming header: \"%c\"",
				//			 copybuf[0]);
                pgmoneta_log_error("unrecognized streaming header: \"%c\"",
							 copybuf[0]);
				goto error;
			}

			/*
			 * Process the received data, and any subsequent data we can read
			 * without blocking.
			 */
			r = CopyStreamReceive(conn, 0, stream->stop_socket, &copybuf);
		}
	}

error:
	if (copybuf != NULL)
		PQfreemem(copybuf);
	return NULL;
}

/*
 * Helper function to parse the result set returned by server after streaming
 * has finished. On failure, prints an error to stderr and returns false.
 */
static bool
ReadEndOfStreamingResult(PGresult *res, XLogRecPtr *startpos, uint32 *timeline)
{
	uint32		startpos_xlogid,
				startpos_xrecoff;

	/*----------
	 * The result set consists of one row and two columns, e.g:
	 *
	 *	next_tli | next_tli_startpos
	 * ----------+-------------------
	 *		   4 | 0/9949AE0
	 *
	 * next_tli is the timeline ID of the next timeline after the one that
	 * just finished streaming. next_tli_startpos is the WAL location where
	 * the server switched to it.
	 *----------
	 */
	if (PQnfields(res) < 2 || PQntuples(res) != 1)
	{
		//pg_log_error("unexpected result set after end-of-timeline: got %d rows and %d fields, expected %d rows and %d fields",
		//			 PQntuples(res), PQnfields(res), 1, 2);
        pgmoneta_log_error("unexpected result set after end-of-timeline: got %d rows and %d fields, expected %d rows and %d fields",
					 PQntuples(res), PQnfields(res), 1, 2);
		return false;
	}

	*timeline = atoi(PQgetvalue(res, 0, 0));
	if (sscanf(PQgetvalue(res, 0, 1), "%X/%X", &startpos_xlogid,
			   &startpos_xrecoff) != 2)
	{
		//pg_log_error("could not parse next timeline's starting point \"%s\"",
		//			 PQgetvalue(res, 0, 1));
        pgmoneta_log_error("could not parse next timeline's starting point \"%s\"",
					 PQgetvalue(res, 0, 1));
		return false;
	}
	*startpos = ((uint64) startpos_xlogid << 32) | startpos_xrecoff;

	return true;
}


/*
 * Check if a timeline history file exists.
 */
static bool
existsTimeLineHistoryFile(StreamCtl *stream)
{
	char		histfname[MAXFNAMELEN];

	/*
	 * Timeline 1 never has a history file. We treat that as if it existed,
	 * since we never need to stream it.
	 */
	if (stream->timeline == 1)
		return true;

	TLHistoryFileName(histfname, stream->timeline);

	return stream->walmethod->existsfile(histfname);
}



static bool
writeTimeLineHistoryFile(StreamCtl *stream, char *filename, char *content)
{
	int			size = strlen(content);
	char		histfname[MAXFNAMELEN];
	Walfile    *f;

	/*
	 * Check that the server's idea of how timeline history files should be
	 * named matches ours.
	 */
	TLHistoryFileName(histfname, stream->timeline);
	if (strcmp(histfname, filename) != 0)
	{
		//pg_log_error("server reported unexpected history file name for timeline %u: %s",
		//			 stream->timeline, filename);
		pgmoneta_log_error("server reported unexpected history file name for timeline %u: %s",
					 stream->timeline, filename);
		return false;
	}

	f = stream->walmethod->open_for_write(histfname, ".tmp", 0);
	if (f == NULL)
	{
		//pg_log_error("could not create timeline history file \"%s\": %s",
		//			 histfname, stream->walmethod->getlasterror());
		pgmoneta_log_error("could not create timeline history file \"%s\": %s",
					 histfname, stream->walmethod->getlasterror());
		return false;
	}

	if ((int) stream->walmethod->write(f, content, size) != size)
	{
		//pg_log_error("could not write timeline history file \"%s\": %s",
		//			 histfname, stream->walmethod->getlasterror());
		pgmoneta_log_error("could not write timeline history file \"%s\": %s",
					 histfname, stream->walmethod->getlasterror());

		/*
		 * If we fail to make the file, delete it to release disk space
		 */
		stream->walmethod->close(f, CLOSE_UNLINK);

		return false;
	}

	if (stream->walmethod->close(f, CLOSE_NORMAL) != 0)
	{
		//pg_log_error("could not close file \"%s\": %s",
		//			 histfname, stream->walmethod->getlasterror());
		pgmoneta_log_error("could not close file \"%s\": %s",
					 histfname, stream->walmethod->getlasterror());
		return false;
	}

	/* Maintain archive_status, check close_walfile() for details. */
	if (stream->mark_done)
	{
		/* writes error message if failed */
		if (!mark_file_as_archived(stream, histfname))
			return false;
	}

	return true;
}



/*
 * Receive a log stream starting at the specified position.
 *
 * Individual parameters are passed through the StreamCtl structure.
 *
 * If sysidentifier is specified, validate that both the system
 * identifier and the timeline matches the specified ones
 * (by sending an extra IDENTIFY_SYSTEM command)
 *
 * All received segments will be written to the directory
 * specified by basedir. This will also fetch any missing timeline history
 * files.
 *
 * The stream_stop callback will be called every time data
 * is received, and whenever a segment is completed. If it returns
 * true, the streaming will stop and the function
 * return. As long as it returns false, streaming will continue
 * indefinitely.
 *
 * If stream_stop() checks for external input, stop_socket should be set to
 * the FD it checks.  This will allow such input to be detected promptly
 * rather than after standby_message_timeout (which might be indefinite).
 * Note that signals will interrupt waits for input as well, but that is
 * race-y since a signal received while busy won't interrupt the wait.
 *
 * standby_message_timeout controls how often we send a message
 * back to the primary letting it know our progress, in milliseconds.
 * Zero means no messages are sent.
 * This message will only contain the write location, and never
 * flush or replay.
 *
 * If 'partial_suffix' is not NULL, files are initially created with the
 * given suffix, and the suffix is removed once the file is finished. That
 * allows you to tell the difference between partial and completed files,
 * so that you can continue later where you left.
 *
 * If 'synchronous' is true, the received WAL is flushed as soon as written,
 * otherwise only when the WAL file is closed.
 *
 * Note: The WAL location *must* be at a log segment start!
 */
bool
ReceiveXlogStream(PGconn *conn, StreamCtl *stream)
{
	char		query[128];
	char		slotcmd[128];
	PGresult   *res;
	XLogRecPtr	stoppos;

	/*
	 * The caller should've checked the server version already, but doesn't do
	 * any harm to check it here too.
	
	if (!CheckServerVersionForStreaming(conn))
		return false;
 */

	/*
	 * Decide whether we want to report the flush position. If we report the
	 * flush position, the primary will know what WAL we'll possibly
	 * re-request, and it can then remove older WAL safely. We must always do
	 * that when we are using slots.
	 *
	 * Reporting the flush position makes one eligible as a synchronous
	 * replica. People shouldn't include generic names in
	 * synchronous_standby_names, but we've protected them against it so far,
	 * so let's continue to do so unless specifically requested.
	 */
	if (stream->replication_slot != NULL)
	{
		reportFlushPosition = true;
		sprintf(slotcmd, "SLOT \"%s\" ", stream->replication_slot);
	}
	else
	{
		if (stream->synchronous)
			reportFlushPosition = true;
		else
			reportFlushPosition = false;
		slotcmd[0] = 0;
	}
    pgmoneta_log_info("ready to start ReceiveXlogStream");
	if (stream->sysidentifier != NULL)
	{
		/* Validate system identifier hasn't changed */
		res = PQexec(conn, "IDENTIFY_SYSTEM");
		if (PQresultStatus(res) != PGRES_TUPLES_OK)
		{
			//pg_log_error("could not send replication command \"%s\": %s",
						 //"IDENTIFY_SYSTEM", PQerrorMessage(conn));
            pgmoneta_log_error("could not send replication command \"%s\": %s", 
                                            "IDENTIFY_SYSTEM", PQerrorMessage(conn));
			PQclear(res);
			return false;
		}
		if (PQntuples(res) != 1 || PQnfields(res) < 3)
		{
			//pg_log_error("could not identify system: got %d rows and %d fields, expected %d rows and %d or more fields",
						 //PQntuples(res), PQnfields(res), 1, 3);
            pgmoneta_log_error("could not identify system: got %d rows and %d fields, expected %d rows and %d or more fields", 
                                            PQntuples(res), PQnfields(res), 1, 3);
			PQclear(res);
			return false;
		}
		if (strcmp(stream->sysidentifier, PQgetvalue(res, 0, 0)) != 0)
		{
			//pg_log_error("system identifier does not match between base backup and streaming connection");
            pgmoneta_log_error("system identifier does not match between base backup and streaming connection");
			PQclear(res);
			return false;
		}
		if (stream->timeline > atoi(PQgetvalue(res, 0, 1)))
		{
			//pg_log_error("starting timeline %u is not present in the server",
			//			 stream->timeline);
            pgmoneta_log_error("starting timeline %u is not present in the server",
						 stream->timeline);
			PQclear(res);
			return false;
		}
		PQclear(res);
	}
    pgmoneta_log_info("ReceiveXlogStream to while loop");
	/*
	 * initialize flush position to starting point, it's the caller's
	 * responsibility that that's sane.
	 */
	lastFlushPosition = stream->startpos;

	while (1)
	{
        /*
		 * Fetch the timeline history file for this timeline, if we don't have
		 * it already. When streaming log to tar, this will always return
		 * false, as we are never streaming into an existing file and
		 * therefore there can be no pre-existing timeline history file.
		 */
		if (!existsTimeLineHistoryFile(stream))
		{
			snprintf(query, sizeof(query), "TIMELINE_HISTORY %u", stream->timeline);
			res = PQexec(conn, query);
			if (PQresultStatus(res) != PGRES_TUPLES_OK)
			{
				/* FIXME: we might send it ok, but get an error */
				//pg_log_error("could not send replication command \"%s\": %s",
				//			 "TIMELINE_HISTORY", PQresultErrorMessage(res));
                pgmoneta_log_error("could not send replication command \"%s\": %s",
							 "TIMELINE_HISTORY", PQresultErrorMessage(res));
				PQclear(res);
				return false;
			}

			/*
			 * The response to TIMELINE_HISTORY is a single row result set
			 * with two fields: filename and content
			 */
			if (PQnfields(res) != 2 || PQntuples(res) != 1)
			{
				//pg_log_warning("unexpected response to TIMELINE_HISTORY command: got %d rows and %d fields, expected %d rows and %d fields",
				//			   PQntuples(res), PQnfields(res), 1, 2);
                pgmoneta_log_error("unexpected response to TIMELINE_HISTORY command: got %d rows and %d fields, expected %d rows and %d fields",
							   PQntuples(res), PQnfields(res), 1, 2);
			}

			/* Write the history file to disk */
			writeTimeLineHistoryFile(stream,
									 PQgetvalue(res, 0, 0),
									 PQgetvalue(res, 0, 1));

			PQclear(res);
		}

		/*
		 * Before we start streaming from the requested location, check if the
		 * callback tells us to stop here.
		 */
		if (stream->stream_stop(stream->startpos, stream->timeline, false))
			return true;

		/* Initiate the replication stream at specified location */
		snprintf(query, sizeof(query), "START_REPLICATION %s%X/%X TIMELINE %u",
				 slotcmd,
				 LSN_FORMAT_ARGS(stream->startpos),
				 stream->timeline);
		pgmoneta_log_info("konglx: query: %s",query);
		res = PQexec(conn, query);
		if (PQresultStatus(res) != PGRES_COPY_BOTH)
		{
			//pg_log_error("could not send replication command \"%s\": %s",
			//			 "START_REPLICATION", PQresultErrorMessage(res));
            pgmoneta_log_error("could not send replication command \"%s\": %s",
						 "START_REPLICATION", PQresultErrorMessage(res));
			PQclear(res);
			return false;
		}
		PQclear(res);

		/* Stream the WAL */
		res = HandleCopyStream(conn, stream, &stoppos);
		if (res == NULL)
			goto error;

		/*
		 * Streaming finished.
		 *
		 * There are two possible reasons for that: a controlled shutdown, or
		 * we reached the end of the current timeline. In case of
		 * end-of-timeline, the server sends a result set after Copy has
		 * finished, containing information about the next timeline. Read
		 * that, and restart streaming from the next timeline. In case of
		 * controlled shutdown, stop here.
		 */
		if (PQresultStatus(res) == PGRES_TUPLES_OK)
		{
			/*
			 * End-of-timeline. Read the next timeline's ID and starting
			 * position. Usually, the starting position will match the end of
			 * the previous timeline, but there are corner cases like if the
			 * server had sent us half of a WAL record, when it was promoted.
			 * The new timeline will begin at the end of the last complete
			 * record in that case, overlapping the partial WAL record on the
			 * old timeline.
			 */
			uint32		newtimeline;
			bool		parsed;

			parsed = ReadEndOfStreamingResult(res, &stream->startpos, &newtimeline);
			PQclear(res);
			if (!parsed)
				goto error;

			/* Sanity check the values the server gave us */
			if (newtimeline <= stream->timeline)
			{
				//pg_log_error("server reported unexpected next timeline %u, following timeline %u",
				//			 newtimeline, stream->timeline);
                pgmoneta_log_error("server reported unexpected next timeline %u, following timeline %u",
							 newtimeline, stream->timeline);
				goto error;
			}
			if (stream->startpos > stoppos)
			{
				/*
                pg_log_error("server stopped streaming timeline %u at %X/%X, but reported next timeline %u to begin at %X/%X",
							 stream->timeline, LSN_FORMAT_ARGS(stoppos),
							 newtimeline, LSN_FORMAT_ARGS(stream->startpos));
                */
                pgmoneta_log_error("server stopped streaming timeline %u at %X/%X, but reported next timeline %u to begin at %X/%X",
							 stream->timeline, LSN_FORMAT_ARGS(stoppos),
							 newtimeline, LSN_FORMAT_ARGS(stream->startpos));
				goto error;
			}

			/* Read the final result, which should be CommandComplete. */
			res = PQgetResult(conn);
			if (PQresultStatus(res) != PGRES_COMMAND_OK)
			{
				//pg_log_error("unexpected termination of replication stream: %s",
				//			 PQresultErrorMessage(res));
                pgmoneta_log_error("unexpected termination of replication stream: %s",
							 PQresultErrorMessage(res));
				PQclear(res);
				goto error;
			}
			PQclear(res);

			/*
			 * Loop back to start streaming from the new timeline. Always
			 * start streaming at the beginning of a segment.
			 */
			stream->timeline = newtimeline;
			stream->startpos = stream->startpos -
				XLogSegmentOffset(stream->startpos, WalSegSz);
			continue;
		}
		else if (PQresultStatus(res) == PGRES_COMMAND_OK)
		{
			PQclear(res);

			/*
			 * End of replication (ie. controlled shut down of the server).
			 *
			 * Check if the callback thinks it's OK to stop here. If not,
			 * complain.
			 */
			if (stream->stream_stop(stoppos, stream->timeline, false))
				return true;
			else
			{
				//pg_log_error("replication stream was terminated before stop point");
                pgmoneta_log_error("replication stream was terminated before stop point");
				goto error;
			}
		}
		else
		{
			/* Server returned an error. 
			pg_log_error("unexpected termination of replication stream: %s",
						 PQresultErrorMessage(res));
            */
            pgmoneta_log_error("unexpected termination of replication stream: %s",
						 PQresultErrorMessage(res));
			PQclear(res);
			goto error;
		}
	}

error:
	if (walfile != NULL && stream->walmethod->close(walfile, CLOSE_NO_RENAME) != 0)
		//pg_log_error("could not close file \"%s\": %s",
		//			 current_walfile_name, stream->walmethod->getlasterror());
        pgmoneta_log_error("could not close file \"%s\": %s",
					 current_walfile_name, stream->walmethod->getlasterror());
	walfile = NULL;
	return false;
}


/*
 * Run IDENTIFY_SYSTEM through a given connection and give back to caller
 * some result information if requested:
 * - System identifier
 * - Current timeline ID
 * - Start LSN position
 * - Database name (NULL in servers prior to 9.4)
 */
bool
RunIdentifySystem(PGconn *conn, char **sysid, TimeLineID *starttli,
				  XLogRecPtr *startpos, char **db_name)
{
	PGresult   *res;
	uint32		hi,
				lo;

	/* Check connection existence */
	//Assert(conn != NULL);
    assert(conn != NULL);

	res = PQexec(conn, "IDENTIFY_SYSTEM");
	if (PQresultStatus(res) != PGRES_TUPLES_OK)
	{
		//pg_log_error("could not send replication command \"%s\": %s",
		//			 "IDENTIFY_SYSTEM", PQerrorMessage(conn));
        pgmoneta_log_error("could not send replication command \"%s\": %s",
					 "IDENTIFY_SYSTEM", PQerrorMessage(conn));
		PQclear(res);
		return false;
	}
	if (PQntuples(res) != 1 || PQnfields(res) < 3)
	{
		//pg_log_error("could not identify system: got %d rows and %d fields, expected %d rows and %d or more fields",
		//			 PQntuples(res), PQnfields(res), 1, 3);
        pgmoneta_log_error("could not identify system: got %d rows and %d fields, expected %d rows and %d or more fields",
					 PQntuples(res), PQnfields(res), 1, 3);
		PQclear(res);
		return false;
	}

	/* Get system identifier */
	if (sysid != NULL)
		*sysid = pg_strdup(PQgetvalue(res, 0, 0));

	/* Get timeline ID to start streaming from */
	if (starttli != NULL)
		*starttli = atoi(PQgetvalue(res, 0, 1));

	/* Get LSN start position if necessary */
	if (startpos != NULL)
	{
		if (sscanf(PQgetvalue(res, 0, 2), "%X/%X", &hi, &lo) != 2)
		{
			//pg_log_error("could not parse write-ahead log location \"%s\"",
			//			 PQgetvalue(res, 0, 2));
            pgmoneta_log_error("could not parse write-ahead log location \"%s\"",
						 PQgetvalue(res, 0, 2));
			PQclear(res);
			return false;
		}
		*startpos = ((uint64) hi) << 32 | lo;
	}

	/* Get database name, only available in 9.4 and newer versions */
	if (db_name != NULL)
	{
		*db_name = NULL;
		if (PQserverVersion(conn) >= 90400)
		{
			if (PQnfields(res) < 4)
			{
				//pg_log_error("could not identify system: got %d rows and %d fields, expected %d rows and %d or more fields",
				//			 PQntuples(res), PQnfields(res), 1, 4);
                pgmoneta_log_error("could not identify system: got %d rows and %d fields, expected %d rows and %d or more fields",
							 PQntuples(res), PQnfields(res), 1, 4);
				PQclear(res);
				return false;
			}
			if (!PQgetisnull(res, 0, 3))
				*db_name = pg_strdup(PQgetvalue(res, 0, 3));
		}
	}

	PQclear(res);
	return true;
}

/*
 * Start the log streaming
 */
static void
StreamLog(void)
{
	XLogRecPtr	serverpos;
	TimeLineID	servertli;
	StreamCtl	stream;
    
	memset(&stream, 0, sizeof(stream)); 
	
	//check version and system
    
	/*
	 * Connect in replication mode to the server
	 */
	// if (conn == NULL){
    //     //conn = GetConnection();
    //     pgmoneta_log_error("connection is null");
    // }
#ifdef panduanconn
	if (!conn)
		/* Error message already written in GetConnection() */
		return;

    
	if (!CheckServerVersionForStreaming(conn))
	{
		/*
		 * Error message already written in CheckServerVersionForStreaming().
		 * There's no hope of recovering from a version mismatch, so don't
		 * retry.
		 */
		exit(1);
	}
#endif
	/*
	 * Identify server, obtaining start LSN position and current timeline ID
	 * at the same time, necessary if not valid data can be found in the
	 * existing output directory.
	 */
	if (!RunIdentifySystem(conn, NULL, &servertli, &serverpos, NULL))
		exit(1);


	/*
	 * Figure out where to start streaming.
	 */
	stream.startpos = FindStreamingStart(&stream.timeline); //according to the largest file id, find the last xlog segment to determine the start 
	//get the destination directory: src/portdirent.c
	//get file, check partial or not, compress or not
	if (stream.startpos == InvalidXLogRecPtr)
	{
		stream.startpos = serverpos;
		stream.timeline = servertli;
	}

	/*
	 * Always start streaming at the beginning of a segment
	 */
	stream.startpos -= XLogSegmentOffset(stream.startpos, WalSegSz);

#ifdef verbose_
	/*
	 * Start the replication
	 */
	if (verbose)//if already configed log output
		pg_log_info("starting log streaming at %X/%X (timeline %u)",
					LSN_FORMAT_ARGS(stream.startpos),
					stream.timeline);
#endif
	stream.stream_stop = stop_streaming;
	stream.stop_socket = PGINVALID_SOCKET;
	stream.standby_message_timeout = standby_message_timeout;
	stream.synchronous = synchronous;
	stream.do_sync = do_sync;
	stream.mark_done = false;
	stream.walmethod = CreateWalDirectoryMethod(basedir, compresslevel,
												stream.do_sync);
	stream.partial_suffix = ".partial";
	stream.replication_slot = replication_slot;

	ReceiveXlogStream(conn, &stream);

	if (!stream.walmethod->finish())
	{
		//pg_log_info("could not finish writing WAL files: %m");
		pgmoneta_log_info("could not finish writing WAL files: %m");
		return;
	}

	PQfinish(conn);
	conn = NULL;

	FreeWalDirectoryMethod();
	pg_free(stream.walmethod);

	conn = NULL;
	
}


int
backup_wal_main(int srv, struct configuration* config, char* d) {
	// d = pgmoneta_append(d, "waltest/");
    // pgmoneta_log_info("ddddd: %s", d);
    // pgmoneta_mkdir(d);
    int			c;
	int			option_index;
	char	   *db_name;
	uint32		hi,
				lo;
    pgmoneta_log_info("start backup wal main");
	basedir = "/home/pgmoneta/pgmoneta/backup/primary/wal/";
    /*connection_string = 
    dbhost = "localhost";
    dbport = "5432";
    dbuser = "repl";
    noloop = 1;
    //--no-password 
    char* pwd = "secretpassword";//hostaddr=127.0.0.1 
    */


	conn = PQconnectdb("host=localhost port=5432 dbname=mydb user=repl password=secretpassword replication=database");//PQsetdbLogin(dbhost, dbport,NULL,NULL,NULL,dbuser,pwd);

    //check connection okay
    if (PQstatus(conn) != CONNECTION_OK)
    {
        fprintf(stderr, "Connection to database failed: %s",
                PQerrorMessage(conn));
        exit_nicely(conn);
    }

	pgmoneta_log_info("conn server connected!");
	
	if (conn == NULL){
        //conn = GetConnection();
        pgmoneta_log_error("connection is null");
    }
	
	
	//wjl todo dbname should be postgres
	auth = pgmoneta_server_authenticate(srv, "mydb", config->users[usr].username, config->users[usr].password, &socket);

	if (auth != AUTH_SUCCESS)
	{
    	pgmoneta_log_trace("Invalid credentials for %s", config->users[usr].username);
    	goto done;
	}

    pgmoneta_log_info("auth server connected!");
	//finish todo 

    /* determine remote server's xlog segment size 
	if (!RetrieveWalSegSize(conn))
    */

    WalSegSz = DEFAULT_XLOG_SEG_SIZE;

	while (true)
	{
		StreamLog();
		if (time_to_stop)
		{
			exit(0);
		}
		else if (noloop)
		{
			//pg_log_error("disconnected");
            pgmoneta_log_error("disconnected");
			exit(1);
		}
		else
		{
			//pg_log_info("disconnected; waiting %d seconds to try again",
			//			RECONNECT_SLEEP_TIME);
            pgmoneta_log_info("disconnected; waiting %d seconds to try again",
						RECONNECT_SLEEP_TIME);
			//pg_usleep(RECONNECT_SLEEP_TIME * 1000000);
            sleep(5);
		}
	}
	//return 1;
done:

	if (socket != -1)
	{
		pgmoneta_disconnect(socket);
	}

	if (!config->servers[srv].valid)
	{
		pgmoneta_log_error("Server %s need wal_level at replica or logical", config->servers[srv].name);
	}

}
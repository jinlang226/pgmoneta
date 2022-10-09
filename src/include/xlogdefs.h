/* ----------------------------------------------------------------
 *				Section 3:	standard system types
 * ----------------------------------------------------------------
 */

/*
 * Pointer
 *		Variable holding address of any memory resident object.
 *
 *		XXX Pointer arithmetic is done with this, so it can't be void *
 *		under "true" ANSI compilers.
 */
typedef char *Pointer;

/*
 * intN
 *		Signed integer, EXACTLY N BITS IN SIZE,
 *		used for numerical computations and the
 *		frontend/backend protocol.
 */
#ifndef HAVE_INT8
typedef signed char int8;		/* == 8 bits */
typedef signed short int16;		/* == 16 bits */
typedef signed int int32;		/* == 32 bits */
#endif							/* not HAVE_INT8 */

/*
 * uintN
 *		Unsigned integer, EXACTLY N BITS IN SIZE,
 *		used for numerical computations and the
 *		frontend/backend protocol.
 */
#ifndef HAVE_UINT8
typedef unsigned char uint8;	/* == 8 bits */
typedef unsigned short uint16;	/* == 16 bits */
typedef unsigned int uint32;	/* == 32 bits */
#endif							/* not HAVE_UINT8 */

/*
 * bitsN
 *		Unit of bitwise operation, AT LEAST N BITS IN SIZE.
 */
typedef uint8 bits8;			/* >= 8 bits */
typedef uint16 bits16;			/* >= 16 bits */
typedef uint32 bits32;			/* >= 32 bits */

#define HAVE_LONG_INT_64 //klx added
/*
 * 64-bit integers
 */
#ifdef HAVE_LONG_INT_64
/* Plain "long int" fits, use it */

#ifndef HAVE_INT64
typedef long int int64;
#endif
#ifndef HAVE_UINT64
typedef unsigned long int uint64;
#endif
#define INT64CONST(x)  (x##L)
#define UINT64CONST(x) (x##UL)
#elif defined(HAVE_LONG_LONG_INT_64)
/* We have working support for "long long int", use that */

#ifndef HAVE_INT64
typedef long long int int64;
#endif
#ifndef HAVE_UINT64
typedef unsigned long long int uint64;
#endif
#define INT64CONST(x)  (x##LL)
#define UINT64CONST(x) (x##ULL)
#else
/* neither HAVE_LONG_INT_64 nor HAVE_LONG_LONG_INT_64 
#error must have a working 64-bit integer datatype*/
#endif


/*
 * xlogdefs.h
 *
 * Postgres write-ahead log manager record pointer and
 * timeline number definitions
 *
 * Portions Copyright (c) 1996-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/xlogdefs.h
 */
#ifndef XLOG_DEFS_H
#define XLOG_DEFS_H

#include <fcntl.h>				/* need open() flags */

/*
 * Pointer to a location in the XLOG.  These pointers are 64 bits wide,
 * because we don't want them ever to overflow.
 */
typedef uint64 XLogRecPtr;

/*
 * Zero is used indicate an invalid pointer. Bootstrap skips the first possible
 * WAL segment, initializing the first WAL page at WAL segment size, so no XLOG
 * record can begin at zero.
 */
#define InvalidXLogRecPtr	0
#define XLogRecPtrIsInvalid(r)	((r) == InvalidXLogRecPtr)

/*
 * First LSN to use for "fake" LSNs.
 *
 * Values smaller than this can be used for special per-AM purposes.
 */
#define FirstNormalUnloggedLSN	((XLogRecPtr) 1000)

/*
 * CppAsString
 *		Convert the argument to a string, using the C preprocessor.
 * CppAsString2
 *		Convert the argument to a string, after one round of macro expansion.
 * CppConcat
 *		Concatenate two arguments together, using the C preprocessor.
 *
 * Note: There used to be support here for pre-ANSI C compilers that didn't
 * support # and ##.  Nowadays, these macros are just for clarity and/or
 * backward compatibility with existing PostgreSQL code.
 */
#define CppAsString(identifier) #identifier
#define CppAsString2(x)			CppAsString(x)
#define CppConcat(x, y)			x##y

#define StaticAssertStmt(condition, errmessage) \
	((void) sizeof(struct { int static_assert_failure : (condition) ? 1 : -1; }))

#define StaticAssertExpr(condition, errmessage) \
	StaticAssertStmt(condition, errmessage)

#define AssertVariableIsOfTypeMacro(varname, typename) \
	(StaticAssertExpr(sizeof(varname) == sizeof(typename), \
	 CppAsString(varname) " does not have type " CppAsString(typename)))

/*
 * Handy macro for printing XLogRecPtr in conventional format, e.g.,
 *
 * printf("%X/%X", LSN_FORMAT_ARGS(lsn));
 */
#define LSN_FORMAT_ARGS(lsn) (AssertVariableIsOfTypeMacro((lsn), XLogRecPtr), (uint32) ((lsn) >> 32)), ((uint32) (lsn))

/*
 * XLogSegNo - physical log file sequence number.
 */
typedef uint64 XLogSegNo;

/*
 * TimeLineID (TLI) - identifies different database histories to prevent
 * confusion after restoring a prior state of a database installation.
 * TLI does not change in a normal stop/restart of the database (including
 * crash-and-recover cases); but we must assign a new TLI after doing
 * a recovery to a prior state, a/k/a point-in-time recovery.  This makes
 * the new WAL logfile sequence we generate distinguishable from the
 * sequence that was generated in the previous incarnation.
 */
typedef uint32 TimeLineID;

/*
 * Replication origin id - this is located in this file to avoid having to
 * include origin.h in a bunch of xlog related places.
 */
typedef uint16 RepOriginId;

/*
 *	Because O_DIRECT bypasses the kernel buffers, and because we never
 *	read those buffers except during crash recovery or if wal_level != minimal,
 *	it is a win to use it in all cases where we sync on each write().  We could
 *	allow O_DIRECT with fsync(), but it is unclear if fsync() could process
 *	writes not buffered in the kernel.  Also, O_DIRECT is never enough to force
 *	data to the drives, it merely tries to bypass the kernel cache, so we still
 *	need O_SYNC/O_DSYNC.
 */
#ifdef O_DIRECT
#define PG_O_DIRECT				O_DIRECT
#else
#define PG_O_DIRECT				0
#endif

/*
 * This chunk of hackery attempts to determine which file sync methods
 * are available on the current platform, and to choose an appropriate
 * default method.  We assume that fsync() is always available, and that
 * configure determined whether fdatasync() is.
 */
#if defined(O_SYNC)
#define OPEN_SYNC_FLAG		O_SYNC
#elif defined(O_FSYNC)
#define OPEN_SYNC_FLAG		O_FSYNC
#endif

#if defined(O_DSYNC)
#if defined(OPEN_SYNC_FLAG)
/* O_DSYNC is distinct? */
#if O_DSYNC != OPEN_SYNC_FLAG
#define OPEN_DATASYNC_FLAG		O_DSYNC
#endif
#else							/* !defined(OPEN_SYNC_FLAG) */
/* Win32 only has O_DSYNC */
#define OPEN_DATASYNC_FLAG		O_DSYNC
#endif
#endif

#if defined(PLATFORM_DEFAULT_SYNC_METHOD)
#define DEFAULT_SYNC_METHOD		PLATFORM_DEFAULT_SYNC_METHOD
#elif defined(OPEN_DATASYNC_FLAG)
#define DEFAULT_SYNC_METHOD		SYNC_METHOD_OPEN_DSYNC
#elif defined(HAVE_FDATASYNC)
#define DEFAULT_SYNC_METHOD		SYNC_METHOD_FDATASYNC
#else
#define DEFAULT_SYNC_METHOD		SYNC_METHOD_FSYNC
#endif

#endif							/* XLOG_DEFS_H */

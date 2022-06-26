

#ifdef __cplusplus
extern "C" {
#endif
#include <xlogdefs.h>
#include <walmethods.h>
/*
 * Called before trying to read more data or when a segment is
 * finished. Return true to stop streaming.
 */
typedef bool (*stream_stop_callback) (XLogRecPtr segendpos, uint32 timeline, bool segment_finished);

/*
 * Global parameters when receiving xlog stream. For details about the individual fields,
 * see the function comment for ReceiveXlogStream().
 */
typedef struct StreamCtl
{
	XLogRecPtr	startpos;		/* Start position for streaming */
	TimeLineID	timeline;		/* Timeline to stream data from */
	char	   *sysidentifier;	/* Validate this system identifier and
								 * timeline */
	int			standby_message_timeout;	/* Send status messages this often */
	bool		synchronous;	/* Flush immediately WAL data on write */
	bool		mark_done;		/* Mark segment as done in generated archive */
	bool		do_sync;		/* Flush to disk to ensure consistent state of
								 * data */

	stream_stop_callback stream_stop;	/* Stop streaming when returns true */

	//pgsocket
    int	stop_socket;	/* if valid, watch for input on this socket
								 * and check stream_stop() when there is any */

	WalWriteMethod *walmethod;	/* How to write the WAL */
	char	   *partial_suffix; /* Suffix appended to partially received files */
	char	   *replication_slot;	/* Replication slot to use, or NULL */
} StreamCtl;

/**
 * backup wal from server to specific directory
 */
int
backup_wal_main(int srv, struct configuration* config, char* d);

#ifdef __cplusplus
}
#endif

/*
* License: BSD-style license
* Copyright: Radek Podgorny <radek@podgorny.cz>,
*            Bernd Schubert <bernd-schubert@gmx.de>
*/

#ifndef UNIONFS_H
#define UNIONFS_H

#include <pthread.h>

#define PATHLEN_MAX 1024
#define HIDETAG "_HIDDEN~"

#define METANAME ".unionfs"
#define METADIR (METANAME  "/") // string concetanation!

// fuse meta files, we might want to hide those
#define FUSE_META_FILE ".fuse_hidden"
#define FUSE_META_LENGTH 12

// file access protection mask
#define S_PROT_MASK (S_ISUID| S_ISGID | S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO)

typedef struct {
	char *path;
	int path_len;		// strlen(path)
	int fd;			 // used to prevent accidental umounts of path
	unsigned char rw;	 // the writable flag
} branch_entry_t;

extern struct fuse_operations unionfs_oper;


// poll_observer_function is run as a thread that is used to observe files for poll() notifications 
extern void *poll_observer_function(void *data);

// mutex to protectect the observer-related data structures below
extern pthread_mutex_t poll_observer_mutex; 

// file descriptors of a pipe the poll_observer thread (also) waits for,
// and the unionfs main thread writes to wake up the poll_observer when
// another call to unionfs_poll indicates more/changed work to do
extern int poll_observer_pipe[2]; 

// if file descriptor X is to be observed for poll() notifications,
//  poll_handle[X] will contain a fuse_pollhandle * for this - or a zero-pointer if not.
extern struct fuse_pollhandle ** poll_handles;
extern short * poll_revents; // what to (still) poll() for, same size as poll_handles
extern unsigned int poll_handles_size; // poll_handles is dynamically enlarged if required for a higher fd


#endif

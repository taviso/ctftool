#ifndef __MESSAGES_H
#define __MESSAGES_H

// The last thread message received.
// TODO: Locking.
extern MSG LastMsg;

DWORD WINAPI MessageHandlerThread(PVOID Parameter);

#endif

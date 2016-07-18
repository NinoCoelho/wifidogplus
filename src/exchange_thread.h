#ifndef _EXCHANGE_THREAD__
#define _EXCHANGE_THREAD__

typedef int (*REQPROCESS)(char *);

void thread_exg_protocol(char *arg);

#endif  // _EXCHANGE_THREAD__



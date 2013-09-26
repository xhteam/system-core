#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <utils/Log.h>
#include <auth_event.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include <pthread.h>
#include "auth_log.h"

static pthread_mutex_t listMutex;
#define MUTEX_ACQUIRE() pthread_mutex_lock(&listMutex)
#define MUTEX_RELEASE() pthread_mutex_unlock(&listMutex)
#define MUTEX_INIT() pthread_mutex_init(&listMutex, NULL)
#define MUTEX_DESTROY() pthread_mutex_destroy(&listMutex)

#ifndef timeradd
#define timeradd(tvp, uvp, vvp)						\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;       \
		if ((vvp)->tv_usec >= 1000000) {			\
			(vvp)->tv_sec++;				\
			(vvp)->tv_usec -= 1000000;			\
		}							\
	} while (0)
#endif

#ifndef timercmp
#define timercmp(a, b, op)               \
        ((a)->tv_sec == (b)->tv_sec      \
        ? (a)->tv_usec op (b)->tv_usec   \
        : (a)->tv_sec op (b)->tv_sec)
#endif

#ifndef timersub
#define timersub(a, b, res)                           \
    do {                                              \
        (res)->tv_sec = (a)->tv_sec - (b)->tv_sec;    \
        (res)->tv_usec = (a)->tv_usec - (b)->tv_usec; \
        if ((res)->tv_usec < 0) {                     \
            (res)->tv_usec += 1000000;                \
            (res)->tv_sec -= 1;                       \
        }                                             \
    } while(0);
#endif

static fd_set readFds;
static int nfds = 0;

static struct auth_event * watch_table[MAX_FD_EVENTS];
static struct auth_event timer_list;
static struct auth_event pending_list;

#define DEBUG 0

#if DEBUG
#define dlog(x...) DBG( x )
static void dump_event(struct auth_event * ev)
{
    dlog("~~~~ Event %x ~~~~\n", (unsigned int)ev);
    dlog("     next    = %x\n", (unsigned int)ev->next);
    dlog("     prev    = %x\n", (unsigned int)ev->prev);
    dlog("     fd      = %d\n", ev->fd);
    dlog("     pers    = %d\n", ev->persist);
    dlog("     timeout = %ds + %dus\n", (int)ev->timeout.tv_sec, (int)ev->timeout.tv_usec);
    dlog("     func    = %x\n", (unsigned int)ev->func);
    dlog("     param   = %x\n", (unsigned int)ev->param);
    dlog("~~~~~~~~~~~~~~~~~~\n");
}
#else
#define dlog(x...) do {} while(0)
#define dump_event(x) do {} while(0)
#endif

static void getNow(struct timeval * tv)
{
#ifdef HAVE_POSIX_CLOCKS
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    tv->tv_sec = ts.tv_sec;
    tv->tv_usec = ts.tv_nsec/1000;
#else
    gettimeofday(tv, NULL);
#endif
}

static void init_list(struct auth_event * list)
{
    memset(list, 0, sizeof(struct auth_event));
    list->next = list;
    list->prev = list;
    list->fd = -1;
}

static void addToList(struct auth_event * ev, struct auth_event * list)
{
    ev->next = list;
    ev->prev = list->prev;
    ev->prev->next = ev;
    list->prev = ev;
    dump_event(ev);
}

static void removeFromList(struct auth_event * ev)
{
    dlog("~~~~ Removing event ~~~~\n");
    dump_event(ev);

    ev->next->prev = ev->prev;
    ev->prev->next = ev->next;
    ev->next = NULL;
    ev->prev = NULL;
}


static void removeWatch(struct auth_event * ev, int index)
{
	int i;
    watch_table[index] = NULL;
    ev->index = -1;

    FD_CLR(ev->fd, &readFds);

    if (ev->fd+1 == nfds) {
        int n = 0;

        for (i = 0; i < MAX_FD_EVENTS; i++) {
            struct auth_event * rev = watch_table[i];

            if ((rev != NULL) && (rev->fd > n)) {
                n = rev->fd;
            }
        }
        nfds = n + 1;
        dlog("~~~~ nfds = %d ~~~~\n", nfds);
    }
}

static void processTimeouts()
{
    dlog("~~~~ +processTimeouts ~~~~\n");
    MUTEX_ACQUIRE();
    struct timeval now;
    struct auth_event * tev = timer_list.next;
    struct auth_event * next;

    getNow(&now);
    // walk list, see if now >= ev->timeout for any events

    dlog("~~~~ Looking for timers <= %ds + %dus ~~~~\n", (int)now.tv_sec, (int)now.tv_usec);
    while ((tev != &timer_list) && (timercmp(&now, &tev->timeout, >))) {
        // Timer expired
        dlog("~~~~ firing timer ~~~~\n");
        next = tev->next;
        removeFromList(tev);
        addToList(tev, &pending_list);
        tev = next;
    }
    MUTEX_RELEASE();
    dlog("~~~~ -processTimeouts ~~~~\n");
}

static void processReadReadies(fd_set * rfds, int n)
{
	int i;
    dlog("~~~~ +processReadReadies (%d) ~~~~\n", n);
    MUTEX_ACQUIRE();

    for (i = 0; (i < MAX_FD_EVENTS) && (n > 0); i++) {
        struct auth_event * rev = watch_table[i];
        if (rev != NULL && FD_ISSET(rev->fd, rfds)) {
            addToList(rev, &pending_list);
            if (rev->persist == false) {
                removeWatch(rev, i);
            }
            n--;
        }
    }

    MUTEX_RELEASE();
    dlog("~~~~ -processReadReadies (%d) ~~~~\n", n);
}

static void firePending()
{
    dlog("~~~~ +firePending ~~~~\n");
    struct auth_event * ev = pending_list.next;
    while (ev != &pending_list) {
        struct auth_event * next = ev->next;
        removeFromList(ev);
        ev->func(ev->fd, 0, ev->param);
        ev = next;
    }
    dlog("~~~~ -firePending ~~~~\n");
}

static int calcNextTimeout(struct timeval * tv)
{
    struct auth_event * tev = timer_list.next;
    struct timeval now;

    getNow(&now);

    // Sorted list, so calc based on first node
    if (tev == &timer_list) {
        // no pending timers
        return -1;
    }

    dlog("~~~~ now = %ds + %dus ~~~~\n", (int)now.tv_sec, (int)now.tv_usec);
    dlog("~~~~ next = %ds + %dus ~~~~\n",
            (int)tev->timeout.tv_sec, (int)tev->timeout.tv_usec);
    if (timercmp(&tev->timeout, &now, >)) {
        timersub(&tev->timeout, &now, tv);
    } else {
        // timer already expired.
        tv->tv_sec = tv->tv_usec = 0;
    }
    return 0;
}

// Initialize internal data structs
void auth_event_init()
{
    MUTEX_INIT();

    FD_ZERO(&readFds);
    init_list(&timer_list);
    init_list(&pending_list);
    memset(watch_table, 0, sizeof(watch_table));
}

// Initialize an event
void auth_event_set(struct auth_event * ev, int fd, bool persist, auth_event_cb func, void * param)
{
    dlog("~~~~ auth_event_set %x ~~~~\n", (unsigned int)ev);
    memset(ev, 0, sizeof(struct auth_event));
    ev->fd = fd;
    ev->index = -1;
    ev->persist = persist;
    ev->func = func;
    ev->param = param;
    fcntl(fd, F_SETFL, O_NONBLOCK);
}

// Add event to watch list
void auth_event_add(struct auth_event * ev)
{
	int i;
    dlog("~~~~ +auth_event_add ~~~~\n");
    MUTEX_ACQUIRE();
    for ( i = 0; i < MAX_FD_EVENTS; i++) {
        if (watch_table[i] == NULL) {
            watch_table[i] = ev;
            ev->index = i;
            dlog("~~~~ added at %d ~~~~\n", i);
            dump_event(ev);
            FD_SET(ev->fd, &readFds);
            if (ev->fd >= nfds) nfds = ev->fd+1;
            dlog("~~~~ nfds = %d ~~~~\n", nfds);
            break;
        }
    }
    MUTEX_RELEASE();
    dlog("~~~~ -auth_event_add ~~~~\n");
}

// Add timer event
void auth_timer_add(struct auth_event * ev, struct timeval * tv)
{
    dlog("~~~~ +ril_timer_add ~~~~\n");
    MUTEX_ACQUIRE();

    struct auth_event * list;
    if (tv != NULL) {
        // add to timer list
        list = timer_list.next;
        ev->fd = -1; // make sure fd is invalid

        struct timeval now;
        getNow(&now);
        timeradd(&now, tv, &ev->timeout);

        // keep list sorted
        while (timercmp(&list->timeout, &ev->timeout, < )
                && (list != &timer_list)) {
            list = list->next;
        }
        // list now points to the first event older than ev
        addToList(ev, list);
    }

    MUTEX_RELEASE();
    dlog("~~~~ -ril_timer_add ~~~~\n");
}

// Remove event from watch or timer list
void auth_event_del(struct auth_event * ev)
{
    dlog("~~~~ +auth_event_del ~~~~\n");
    MUTEX_ACQUIRE();

    if (ev->index < 0 || ev->index >= MAX_FD_EVENTS) {
        return;
    }

    removeWatch(ev, ev->index);

    MUTEX_RELEASE();
    dlog("~~~~ -auth_event_del ~~~~\n");
}

#if DEBUG
static void printReadies(fd_set * rfds)
{
	int i;
    for (i = 0; (i < MAX_FD_EVENTS); i++) {
        struct auth_event * rev = watch_table[i];
        if (rev != NULL && FD_ISSET(rev->fd, rfds)) {
          dlog("DON: fd=%d is ready\n", rev->fd);
        }
    }
}
#else
#define printReadies(rfds) do {} while(0)
#endif

void auth_event_loop()
{
    int n;
    fd_set rfds;
    struct timeval tv;
    struct timeval * ptv;


    for (;;) {

        // make local copy of read fd_set
        memcpy(&rfds, &readFds, sizeof(fd_set));
        if (-1 == calcNextTimeout(&tv)) {
            // no pending timers; block indefinitely
            dlog("~~~~ no timers; blocking indefinitely ~~~~\n");
            ptv = NULL;
        } else {
            dlog("~~~~ blocking for %ds + %dus ~~~~\n", (int)tv.tv_sec, (int)tv.tv_usec);
            ptv = &tv;
        }
        printReadies(&rfds);
        n = select(nfds, &rfds, NULL, NULL, ptv);
        printReadies(&rfds);
        dlog("~~~~ %d events fired ~~~~\n", n);
        if (n < 0) {
            if (errno == EINTR) continue;

            dlog("auth_event: select error (%d)\n", errno);
            // bail?
            return;
        }

        // Check for timeouts
        processTimeouts();
        // Check for read-ready
        processReadReadies(&rfds, n);
        // Fire away
        firePending();
    }
}

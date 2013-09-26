
#ifndef _AUTH_EVENT_H
#define _AUTH_EVENT_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdbool.h>

// Max number of fd's we watch at any one time.  Increase if necessary.
#define MAX_FD_EVENTS 8

typedef void (*auth_event_cb)(int fd, short events, void *userdata);

struct auth_event {
    struct auth_event *next;
    struct auth_event *prev;

    int fd;
    int index;
    bool persist;
    struct timeval timeout;
    auth_event_cb func;
    void *param;
};

// Initialize internal data structs
void auth_event_init();

// Initialize an event
void auth_event_set(struct auth_event * ev, int fd, bool persist, auth_event_cb func, void * param);

// Add event to watch list
void auth_event_add(struct auth_event * ev);

// Add timer event
void auth_timer_add(struct auth_event * ev, struct timeval * tv);

// Remove event from watch list
void auth_event_del(struct auth_event * ev);

// Event loop
void auth_event_loop();

#if defined(__cplusplus)
}
#endif

#endif


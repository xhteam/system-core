#ifndef _AUTH_CORE_H_
#define _AUTH_CORE_H_

#include <linux/types.h>

#include "auth_log.h"
#include "auth_proto.h"

#define AUTHENTICATOR_VERSION	"v1.0.3"
#define AUTHENTICATOR_FAMILY 0x44
//below time is s based
#define AUTHENTICATOR_START_DELAY 2 
#define AUTHENTICATOR_INTERVAL	  30 
#define AUTHENTICATOR_RETRY		  5 
#define AUTHENTICATOR_PASS_RETRY  100




#define INIT_STATE_INVALID 0
#define INIT_STATE_INITED  1
#define INIT_STATE_STARTED 2
#define INIT_STATE_STOPPED 3

#define AUTH_STATE_OKAY    0
#define AUTH_STATE_FAILED  1
#define AUTH_STATE_LOCKED  2

#define INIT_STATE(obj) (obj->status.init_state)
#define AUTH_STATE(obj) (obj->status.auth_state)


typedef struct authenticator_status
{
	uint32_t init_state:2;
	uint32_t auth_state:3;
}authenticator_status_t;


//internal data
struct authenticator_core;
typedef struct authenticator_core authenticator_core_t;
	
struct authenticator;
typedef struct authenticator authenticator;

typedef void (*TimedCallback) (void *param);

int authenticator_init(struct authenticator** obj);
int authenticator_dispose(struct authenticator* obj);
int authenticator_start(struct authenticator* obj);

//reset bus of mid ,0 means default mid
int authenticator_reset_bus(uint32_t mid);

//wrapper for read/write operations
int authenticator_slave_read(uint8_t* dat,int length);
int authenticator_slave_write(uint8_t* dat,int length);
int authenticator_master_read(uint8_t* dat,int length);
int authenticator_master_write(uint8_t* dat,int length);


int authenticator_get_rn(struct w1_reg_num *rn);
int authenticator_get_mid(uint32_t* mid);


void requestTimedCallback (TimedCallback callback, void *param,const struct timeval *relativeTime);


//
//internal utils
//
//legacy search utils
int search_masters(uint32_t ids[]) ;
int search_slaves(uint32_t id,uint8_t family_to_search); 

int set_master_autosearch(uint32_t id,bool enable);


long simple_strtol(const char *cp,char **endp,unsigned int base);
int ustrtoul(const char *cp, char **endp, unsigned int base);
unsigned long simple_strtoul(const char *cp,char **endp,unsigned int base);




#endif


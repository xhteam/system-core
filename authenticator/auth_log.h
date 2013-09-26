#ifndef _AUTH_LOG_H
#define _AUTH_LOG_H


#include <linux/types.h>
enum
{
	AUTHLOG_WARN			=0x1,
	AUTHLOG_INFO			=0x2,
	AUTHLOG_ERROR			=0x4,
	AUTHLOG_DEBUG			=0x8,	
	AUTHLOG_VERBOSE			=0x10,
};


extern uint32_t auth_log_level;	



int __log_print(const char *fmt, ...);

#define VERBOSE(...) \
	do{if(auth_log_level&AUTHLOG_VERBOSE) __log_print(__VA_ARGS__);}while(0)

#define WARN(...) \
	do{if(auth_log_level&AUTHLOG_WARN) __log_print(__VA_ARGS__);}while(0)

#define INFO(...) \
	do{if(auth_log_level&AUTHLOG_INFO) __log_print(__VA_ARGS__);}while(0)	

#define ERROR(...) \
	do{if(auth_log_level&AUTHLOG_ERROR) __log_print(__VA_ARGS__);}while(0)

#define DBG(...) \
	do{if(auth_log_level&AUTHLOG_DEBUG) __log_print(__VA_ARGS__);}while(0)


#define ALWAYS(...) \
	do{__log_print(__VA_ARGS__);}while(0)

void dump_data(const char *function,const uint8_t *data ,int size);


#endif


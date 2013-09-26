#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/types.h>
#include "auth_core.h"


static void usage(void)
{
	INFO("Usage: authenticator [options] [output file]\n"
		"\n"
		"\t-h\tthis help screen\n"
		"\t-l\tlist masters\n"
		"\n");
}



int main(int argc, char *argv[])
{

	int s;
	bool list_master = false;
	struct authenticator* thiz;

	while ((s = getopt(argc, argv, "hl")) != -1) {
		switch (s){
		case 'l':
			list_master = true;
			break;

		case 'h':
		default:
			/* getopt() outputs an error for us */
			usage();
			return 1;
		}
	}

	if(authenticator_init(&thiz))
	{
		ERROR("init authenticator failed\n");
	}
	else
	{
	    //will not return
		authenticator_start(thiz);		
	}

    //to avoid service always restart me if init failed, run a dead loop is good solution
    while(1){
        //sleep(UINT32_MAX) seems to return immediately on bionic
        sleep(0x00ffffff);
    }
	
	
	return 0;
}


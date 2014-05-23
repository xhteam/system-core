#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>
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

static int read_revision_file( const char* file, int* pResult )
{
    int fd = -1;
    fd = open( file, O_RDONLY );
    if( fd >= 0 ){
        char buf[20];
        int rlt = read( fd, buf, sizeof(buf) );
        if( rlt > 0 ){
			int l;
            buf[rlt] = '\0';
			l = strlen(buf);
			if(buf[0]=='v')
				memmove(&buf[0],&buf[1],l);
            *pResult = atoi(buf);
			close(fd);
            return 0;
        }
    }
    return -1;
}


int main(int argc, char *argv[])
{
	int s;
	bool list_master = false;
	bool bus_write=false;
	bool bus_read=false;
	int v=0;
	int rev=0;
	struct authenticator* thiz;

	if(!read_revision_file("/proc/boardrev",&rev)){
		if(rev>2){
			DBG("skip authenticator since boardrev over 2\n");
			goto release_cpu_loop;
		}
	}
	while ((s = getopt(argc, argv, "?hlw:")) != -1) {
		switch (s){
		case 'l':
			list_master = true;
			break;
		case 'r':
			bus_read=true;
			break;
		case 'w':
			bus_write=true;
			v = simple_strtoul(optarg,0,16);
			break;
		case 'h':
		case '?':
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
		if(bus_write){
			uint8_t value = (uint8_t)v; 
			authenticator_reset_bus(0);
			while(true){				
				ALWAYS("bus write 0x%x\n",value);
				authenticator_master_write(&value,1);
				sleep(5);
			}
		}else if (bus_read){
			uint8_t value;
			ALWAYS("bus read test\n");
			authenticator_reset_bus(0);
			while(true){
				authenticator_master_read(&value,1);
				ALWAYS("bus read value=0x%x\n",value);				
				sleep(5);
			}
			
		}else {
		    //will not return
			authenticator_start(thiz);		
		}
	}

release_cpu_loop:
	//to avoid service always restart me if init failed, run a dead loop is good solution
    while(1){
        //sleep(UINT32_MAX) seems to return immediately on bionic
        sleep(0x00ffffff);
    }
	
	
	return 0;
}


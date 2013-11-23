#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <utils/Log.h>
#ifdef LEGACY_UI
#include <binder/IPCThreadState.h>
#include <binder/ProcessState.h>
#endif
#include <utils/threads.h>
#include <cutils/properties.h>

#include "auth_core.h"
#include "auth_event.h"
#include "auth_algo.h"
#include "auth_screen.h"

using namespace android;

struct cpu_info {
    long unsigned utime, ntime, stime, itime;
    long unsigned iowtime, irqtime, sirqtime;
};


typedef struct UserCallbackInfo {
    TimedCallback p_callback;
    void *userParam;
    struct auth_event event;
    struct UserCallbackInfo *p_next;
} UserCallbackInfo;

struct authenticator_core
{
	int started;
	pthread_t tid_auth_core;
	pthread_mutex_t startupMutex;
	pthread_cond_t  startupCond;

	int fdWakeupRead;
	int fdWakeupWrite;
	struct auth_event wakeupfd_event;


	auth_algorithm_t algo;

    bool multi_lock;
    int  retries;

	//statistics
	int fail;
	int pass;
	//
	//UserCallbackInfo *last_wake_timeout_info;
	struct cpu_info old_cpu;
	struct cpu_info new_cpu;
};


struct authenticator{	
	authenticator_status_t status;

	//bus relevant 
	uint32_t mid;
	struct w1_reg_num rn;
	
	int s; //socket to kernel connector
	FILE* out; //message dump 

	int32_t (*read)(struct authenticator* me,uint8_t* dat,int32_t length);
	int32_t (*write)(struct authenticator* me,uint8_t* dat,int32_t length);	
	int send_seq;

	//intenal struct
	authenticator_core_t* core;
};




uint32_t auth_log_level = AUTHLOG_ERROR|AUTHLOG_DEBUG;
static struct authenticator* global_authenticator=0;
static FILE* def_out = stdout;
static int cpu_stat_threshold=2;

int __log_print(const char *fmt, ...)
{
    va_list ap;
	int ret=0;
    va_start(ap, fmt);
	if(global_authenticator&&global_authenticator->out)
		ret=vfprintf(global_authenticator->out,fmt,ap);
	else if(def_out)
		ret=vfprintf(def_out,fmt,ap);
	else
	{
	    #ifdef LOG_TAG
	    ret=__android_log_vprint(ANDROID_LOG_DEBUG,LOG_TAG,fmt,ap);
        #else
	    ret=__android_log_vprint(ANDROID_LOG_DEBUG,"authenticator",fmt,ap);
        #endif
    }
    va_end(ap);
	return ret;
}

static int get_cpustat(struct cpu_info* cpuinfo){
	FILE *file;
	file = fopen("/proc/stat", "r");
	if (!file) return -1;
	fscanf(file, "cpu  %lu %lu %lu %lu %lu %lu %lu", &cpuinfo->utime, &cpuinfo->ntime, &cpuinfo->stime,
			&cpuinfo->itime, &cpuinfo->iowtime, &cpuinfo->irqtime, &cpuinfo->sirqtime);
	fclose(file);
	return 0;
}

static int get_cpu_utilization(struct authenticator* obj){	
    long unsigned total_delta_time;
	struct cpu_info* oldinfo = &obj->core->old_cpu;
	struct cpu_info* newinfo = &obj->core->new_cpu;
	int total,user,system,iow,irq;

	total=user=system=iow=irq=0;
    total_delta_time = (newinfo->utime + newinfo->ntime + newinfo->stime + newinfo->itime
                        + newinfo->iowtime + newinfo->irqtime + newinfo->sirqtime)
                     - (oldinfo->utime + oldinfo->ntime + oldinfo->stime + oldinfo->itime
                        + oldinfo->iowtime + oldinfo->irqtime + oldinfo->sirqtime);

	if(total_delta_time){
		user = ((newinfo->utime + newinfo->ntime) - (oldinfo->utime + oldinfo->ntime)) * 100  / total_delta_time;
		system = ((newinfo->stime ) - (oldinfo->stime)) * 100 / total_delta_time;
		iow = ((newinfo->iowtime) - (oldinfo->iowtime)) * 100 / total_delta_time;
		irq = ((newinfo->irqtime + newinfo->sirqtime)- (oldinfo->irqtime + oldinfo->sirqtime)) * 100 / total_delta_time;
	}
	total = user+system+iow+irq;

	return total;
}

int authenticator_init(struct authenticator** obj)
{
	int ret=-1;
	int master_count,i;
	uint32_t ids[32];
	uint8_t *pmem;
	struct authenticator* thiz;
	struct sockaddr_nl l_local;
	int found=0;
	int slave_count;
    int ppid = getppid();
	char value[PROPERTY_VALUE_MAX];    

	
	#ifdef LEGACY_UI
    // set up the thread-pool
    sp<ProcessState> proc(ProcessState::self());
    ProcessState::self()->startThreadPool();
	#endif
    //
    //init process pid is always 1
    //if we are forked from init,then disable default output    
    if(1==ppid)
    {
        //disable default output
        def_out = 0;
    }

    //apply new loglevel if possible
    if (property_get("persist.auth.loglevel", value, NULL) > 0) {
        auth_log_level = simple_strtoul(value,0,16);
    }

	
    if (property_get("persist.auth.cpustat", value, "0x2") > 0) {
        cpu_stat_threshold = simple_strtoul(value,0,16);
    }

    ALWAYS("=================\n");
    ALWAYS("authenticator %s [loglevel:0x%x][cpu threshold:%d]\n",AUTHENTICATOR_VERSION,auth_log_level,
		cpu_stat_threshold);
    ALWAYS("=================\n");        

	pmem = (uint8_t *)malloc(sizeof(struct authenticator)+sizeof(authenticator_core_t));
	if(!pmem){
		ERROR("out of memory\n");
		goto out;
	}
	memset(pmem,0,sizeof(struct authenticator)+sizeof(authenticator_core_t));
	//init socket	
	thiz = (struct authenticator *)pmem;
	thiz->s= socket(AF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
	thiz->core = (authenticator_core_t*)(pmem+sizeof(struct authenticator));
	if (thiz->s == -1) {
		ERROR("create netlink socket failed\n",strerror(errno));
		goto free_thiz;
	}

	l_local.nl_family = AF_NETLINK;
	l_local.nl_groups = -1;//CN_W1_IDX;
	l_local.nl_pid    = getpid();
	if (bind(thiz->s, (struct sockaddr *)&l_local, sizeof(struct sockaddr_nl)) == -1) {
		ERROR("bind netlink socket failed[%s]\n",strerror(errno));
		close(thiz->s);
		goto free_thiz;
	}

	global_authenticator = *obj =thiz;

	{
		int j;
		uint32_t* ids=NULL;
		struct w1_reg_num* rns=NULL;
		master_count = auth_proto_search_masters(thiz->s,&ids);
		if(master_count<=0){
			ERROR("no master found\n");
			goto close_socket;
		}
			
		for(i=0;i<master_count;i++){
            //reset bus
            auth_proto_reset_bus(thiz->s,ids[i]);

            INFO("disable autosearch on bus %d \n",ids[i]);
            set_master_autosearch(ids[i],false);
            
			slave_count  = auth_proto_search_slaves(thiz->s,ids[i],&rns);
            INFO("slave count [%d] on bus %d\n",slave_count,ids[i]);
			//only one authenticator supported
			if(slave_count>0)
			{
				for(j=0;j<slave_count;j++)
				{
                    INFO("found slave[%02x.%012llx.%02x] on master[%08x]\n",
                        rns[j].family, (unsigned long long)rns[j].id, rns[j].crc,
                        ids[i]);
					if(rns[j].family == AUTHENTICATOR_FAMILY)
					{
						found=1;
						INFO("found matched slave[%02x.%012llx.%02x] on master[%08x]\n",
							rns[j].family, (unsigned long long)rns[j].id, rns[j].crc,
							ids[i]);
						thiz->mid = ids[i];
						memcpy(&thiz->rn,&rns[j],sizeof(struct w1_reg_num));
						break;
					}
						
				}
			}
			free(rns);
			
			if(found)
				break;
			
		}

		if(ids)
			free(ids);
	
	}
	

	//
	INIT_STATE(thiz) = INIT_STATE_INITED;
	{
		authenticator_core_t* core = thiz->core;
		pthread_mutex_init(&core->startupMutex,NULL);
		pthread_cond_init(&core->startupCond,NULL); 
	}
	/*
	if(!thiz->mid)
	{
		ERROR("no matched authenticator found\n");
		goto close_socket;
	}*/

	return 0;

	
    
close_socket:
	close(thiz->s);
free_thiz:
	free(thiz);
out:
	//failure cases
	// 1  netlink disabled by kernel ;
	// 2  no master bus found;
	// 3  no authentication family chip found;
	// 4  no famliy chip mounted on some revision boards
	// we need to do screen lock for all these cases except some special revision boards.
    property_get("ro.revision", value, "1");
    int boardid = atoi(value);
    if(boardid>=2)//authentication chip only mounted on board id 2 or above
    {
        WARN("authenticator init failed\n");
        property_get("persist.auth.bypass", value, "false");
        if(strcmp(value,"true"))
    	{
            auth_screen_lock(0);
    	}
    }
    else{
        WARN("skip screen lock for board revision %d\n",boardid);
    }

	
	#ifdef LEGACY_UI
    //it will block
    IPCThreadState::self()->joinThreadPool();
    #endif
	
	return ret;
	
}


int authenticator_dispose(struct authenticator* obj)
{
	//TODO
	return 0;
}
int authenticator_reset_bus(uint32_t mid)
{
	if(!global_authenticator||INIT_STATE(global_authenticator)<INIT_STATE_INITED) return 0;
		
	return auth_proto_reset_bus(global_authenticator->s,mid?mid:global_authenticator->mid);
    
}

int authenticator_slave_read(uint8_t* dat,int length)
{
	if(!global_authenticator||INIT_STATE(global_authenticator)<INIT_STATE_INITED) return 0;
		
	return auth_proto_slave_read(global_authenticator->s,&global_authenticator->rn,dat,length);
}
int authenticator_slave_write(uint8_t* dat,int length)
{
	if(!global_authenticator||INIT_STATE(global_authenticator)<INIT_STATE_INITED) return 0;
		
	return auth_proto_slave_write(global_authenticator->s,&global_authenticator->rn,dat,length);
	
}

int authenticator_master_read(uint8_t* dat,int length)
{
	if(!global_authenticator||INIT_STATE(global_authenticator)<INIT_STATE_INITED) return 0;
		
	return auth_proto_master_read(global_authenticator->s,global_authenticator->mid,dat,length);
    
}
int authenticator_master_write(uint8_t* dat,int length)
{
	if(!global_authenticator||INIT_STATE(global_authenticator)<INIT_STATE_INITED) return 0;
		
	return auth_proto_master_write(global_authenticator->s,global_authenticator->mid,dat,length);
    
}
int authenticator_get_rn(struct w1_reg_num *rn)
{
	if(!global_authenticator||INIT_STATE(global_authenticator)<INIT_STATE_INITED) return 0;
		
	memcpy(rn,&global_authenticator->rn,sizeof(struct w1_reg_num));

    return 0;

}
int authenticator_get_mid(uint32_t* mid)
{
	if(!global_authenticator||INIT_STATE(global_authenticator)<INIT_STATE_INITED) return 0;

    *mid = global_authenticator->mid;

    return 0;
    
}

static void authentication_failure_cb (void* param) {
	struct authenticator* thiz = (struct authenticator*)param;
    if(AUTH_STATE_OKAY==AUTH_STATE(thiz)){        
        auth_screen_unlock();
    }
    else{        
        const struct timeval timeval = {5,0};//1s
        auth_screen_lock(NULL);
        AUTH_STATE(thiz)=AUTH_STATE_LOCKED;
        requestTimedCallback(authentication_failure_cb,thiz,&timeval);        
    }
    
}

static void CpuUtilizationCallback (void* param) {
	struct authenticator* thiz = (struct authenticator*)param;		
	struct authenticator_core* core = thiz->core;	
	struct timeval timeval = {AUTHENTICATOR_CPUSTAT_INTERVAL,0};

	memcpy(&core->old_cpu,&core->new_cpu,sizeof(core->new_cpu));
	get_cpustat(&core->new_cpu);
	int cpu_utilization = get_cpu_utilization(thiz);
	INFO("cpustat:%ld%%\n",cpu_utilization);
	
	requestTimedCallback(CpuUtilizationCallback,thiz,&timeval);	
}
static void authenticationProcessCallback (void* param) {
	struct authenticator* thiz = (struct authenticator*)param;		
	struct authenticator_core* core = thiz->core;
    uint64_t romid;
	struct timeval timeval = {AUTHENTICATOR_INTERVAL,0};//10s
	time_t tm;
    struct tm* timeinfo;
	memcpy(&core->old_cpu,&core->new_cpu,sizeof(core->new_cpu));
	get_cpustat(&core->new_cpu);

	int cpu_utilization = get_cpu_utilization(thiz);
	INFO("cpustat:%ld%%\n",cpu_utilization);
	if(!core->pass||(cpu_utilization<cpu_stat_threshold/*very idle to run*/)){
		INFO("authentication start.\n");
		memcpy(&romid,&thiz->rn,sizeof(thiz->rn));
		romid=__cpu_to_le64(romid);
		if(auth_algo_challenge(core->algo,romid)<0)
		{
		    core->retries++;
			core->fail++;
	        if(core->retries>=AUTHENTICATOR_RETRY){
				if(core->pass&&(core->retries<AUTHENTICATOR_PASS_RETRY)){
					//dynamically improve more retries?
					timeval.tv_sec = timeval.tv_sec*2;
					goto retry_once;				
				}
				if(AUTH_STATE_OKAY==AUTH_STATE(thiz)){   		    
	                AUTH_STATE(thiz) = AUTH_STATE_FAILED;
	                if(core->multi_lock){
	                    requestTimedCallback(authentication_failure_cb,thiz,0);
	                }else {
	                    auth_screen_lock(NULL);
	                    AUTH_STATE(thiz) = AUTH_STATE_LOCKED;
	                }
	            }
	        }
		}
	    else
	    {
		    if(AUTH_STATE_OKAY!=AUTH_STATE(thiz))
			{   
			    if(false==core->multi_lock)
			        auth_screen_unlock();
	            AUTH_STATE(thiz) = AUTH_STATE_OKAY;            
	        }
			core->retries=0;
			core->pass++;        
	    }

	retry_once:	
		INFO("\npass[%d]fail[%d]retry[%d]\n",core->pass,core->fail,core->retries);
	
	}

	time(&tm);
    timeinfo = localtime ( &tm );
    timeinfo->tm_sec+=timeval.tv_sec;
    time_t nexttm = mktime(timeinfo);
    char buf[1024];
    sprintf(buf,"next authentication time: ");
    sprintf(buf+strlen(buf),"%.24s\n",ctime(&nexttm));
	INFO(buf);
	requestTimedCallback(authenticationProcessCallback,thiz,&timeval);
	
	
}
/**
 * A write on the wakeup fd is done just to pop us out of select()
 * We empty the buffer here and then ril_event will reset the timers on the
 * way back down
 */
static void processWakeupCallback(int fd, short flags, void *param) {
	authenticator_core_t* core = (authenticator_core_t*)param;

    char buff[16];
    int ret;

    /* empty our wakeup socket out */
    do {
        ret = read(core->fdWakeupRead, &buff, sizeof(buff));
    } while (ret > 0 || (ret < 0 && errno == EINTR));
}

static void userTimerCallback (int fd, short flags, void *param) {
    UserCallbackInfo *p_info;

    p_info = (UserCallbackInfo *)param;

    p_info->p_callback(p_info->userParam);
    free(p_info);
}



static void triggerEvLoop(authenticator_core_t* core) {
    int ret;
    if (!pthread_equal(pthread_self(), core->tid_auth_core)) {
        /* trigger event loop to wakeup. No reason to do this,
         * if we're in the event loop thread */
         do {
            ret = write (core->fdWakeupWrite, " ", 1);
         } while (ret < 0 && errno == EINTR);
    }
}

static void rilEventAddWakeup(authenticator_core_t* core,struct auth_event *ev) {
    auth_event_add(ev);
    triggerEvLoop(core);
}

static void* authenticator_loop(void* param)
{
	struct authenticator* thiz = (struct authenticator*)param;
	authenticator_core_t* core = thiz->core;
	unsigned char buf[1024];
	struct pollfd pfd;
	struct nlmsghdr *reply;	
	struct cn_msg *msg;		
	int s = thiz->s;
	int len;
    int ret;
    int filedes[2];
	



    auth_event_init();

    ret = pipe(filedes);

    if (ret < 0) {
        ERROR("Error in pipe() errno:%d", errno);
        return NULL;
    }

    core->fdWakeupRead = filedes[0];
    core->fdWakeupWrite = filedes[1];

    fcntl(core->fdWakeupRead, F_SETFL, O_NONBLOCK);

    auth_event_set (&core->wakeupfd_event, core->fdWakeupRead, true,
                processWakeupCallback, (void*)core);

    rilEventAddWakeup(core,&core->wakeupfd_event);

	VERBOSE("auth event loop started\n");

    pthread_mutex_lock(&core->startupMutex);

    core->started = 1;
    pthread_cond_broadcast(&core->startupCond);

    pthread_mutex_unlock(&core->startupMutex);

	INIT_STATE(thiz) = INIT_STATE_STARTED;


    // Only returns on error
    auth_event_loop();
    ERROR ("error in event_loop_base errno:%d", errno);

    return NULL;	
}

int authenticator_start(struct authenticator* thiz)
{
	
	#ifdef LEGACY_UI
    // set up the thread-pool
    sp<ProcessState> proc(ProcessState::self());
    ProcessState::self()->startThreadPool();
	#endif
	
	authenticator_core_t* core = thiz->core;
	const struct timeval timeval = {AUTHENTICATOR_START_DELAY,0};//10s	
	const struct timeval timeval_cpustat = {0,0};//10s
    int ret;
    pthread_attr_t attr;

    /* spin up eventLoop thread and wait for it to get started */
    core->started = 0;
    pthread_mutex_lock(&core->startupMutex);

    pthread_attr_init (&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    ret = pthread_create(&core->tid_auth_core, &attr, authenticator_loop, thiz);

    while (core->started == 0) {
        pthread_cond_wait(&core->startupCond, &core->startupMutex);
    }

    pthread_mutex_unlock(&core->startupMutex);

    if (ret < 0) {
        ERROR("Failed to create auth core thread errno:%d", errno);
        return ret;
    }

	auth_algo_init(&core->algo);
    auth_screen_init();

    //
    #ifdef MULTI_LOCK_SUPPORT
    core->multi_lock = true;
    #endif

	get_cpustat(&thiz->core->new_cpu);
	requestTimedCallback(CpuUtilizationCallback,thiz,&timeval_cpustat);
		
	requestTimedCallback(authenticationProcessCallback,thiz,&timeval);

	
	#ifdef LEGACY_UI
    //it will block
    IPCThreadState::self()->joinThreadPool();
	#endif
    return 0;
}



void requestTimedCallback (TimedCallback callback, void *param,const struct timeval *relativeTime)
{
    struct timeval myRelativeTime;
    UserCallbackInfo *p_info;
	if(!global_authenticator||INIT_STATE(global_authenticator)<INIT_STATE_INITED) return;

    p_info = (UserCallbackInfo *) malloc (sizeof(UserCallbackInfo));
	if(p_info)
	{
		p_info->p_callback = callback;
		p_info->userParam = param;
		
		if (relativeTime == NULL) {
			/* treat null parameter as a 0 relative time */
			memset (&myRelativeTime, 0, sizeof(myRelativeTime));
		} else {
			/* FIXME I think event_add's tv param is really const anyway */
			memcpy (&myRelativeTime, relativeTime, sizeof(myRelativeTime));
		}
		
		auth_event_set(&(p_info->event), -1, false, userTimerCallback, p_info);
		
		auth_timer_add(&(p_info->event), &myRelativeTime);
		
		triggerEvLoop(global_authenticator->core);
		
		
	}

	
}

//
//belowing code snippet is not used ,but for maintainers for w1 proto we keep it here,
//Please don't delete them,thank you!
//
#ifdef GOD_SAVING_ME
static void w1_dump_reply( char *prefix, struct w1_netlink_msg *hdr)
{
	struct w1_netlink_cmd *cmd;
	unsigned char *hdr_data = hdr->data;
	unsigned int hdr_len = hdr->len;
	time_t tm;
	int i;

	time(&tm);
	
	while (hdr_len) {
		cmd = (struct w1_netlink_cmd *)hdr_data;
	
		INFO("%.24s : %s ", ctime(&tm), prefix);

		if (cmd->len + sizeof(struct w1_netlink_cmd) > hdr_len) {
			INFO("Malformed message.\n");
			break;
		}

		switch (cmd->cmd) {
			case W1_CMD_READ:
				INFO("READ: ");
				for (i=0; i<cmd->len; ++i)
					INFO( "%02x ", cmd->data[i]);
				INFO( "\n");
				break;
			case W1_CMD_SEARCH:
				{					
					struct w1_reg_num id;	
					uint8_t* data=cmd->data;
					uint16_t length=cmd->len;

					for (i=0; i<length; i++)
					{
						memcpy(&id,data+i*sizeof(struct w1_reg_num),sizeof(struct w1_reg_num));
						INFO( "id=%02x.%012llx.%02x\n", id.family, (unsigned long long)id.id, id.crc);
						length-=sizeof(struct w1_reg_num);
						
					}
					INFO( "\n");
				}
				break;
			default:
				INFO("cmd=%02x, len=%u.\n", cmd->cmd, cmd->len);
				break;
		}

		hdr_data += cmd->len + sizeof(struct w1_netlink_cmd);
		hdr_len -= cmd->len + sizeof(struct w1_netlink_cmd);
	}
}

static void w1_msg_master_reply(struct w1_netlink_msg *hdr)
{
	char prefix[128];

	snprintf(prefix, sizeof(prefix), "master: id=%08x", hdr->id.mst.id);
	w1_dump_reply(prefix, hdr);
}

static void w1_msg_slave_reply(struct w1_netlink_msg *hdr)
{
	char prefix[128];
	struct w1_reg_num id;
				
	memcpy(&id, hdr->id.id, sizeof(id));

	snprintf(prefix, sizeof(prefix), "slave: id=%02x.%012llx.%02x",
		id.family, (unsigned long long)id.id, id.crc); 
	w1_dump_reply(prefix, hdr);
}
static void w1_msg_list_master(struct w1_netlink_msg *hdr)
{
	uint32_t * id=(uint32_t*)(hdr+1);			
	unsigned int hdr_length=hdr->len;	
	time_t tm;
	time(&tm);
	if(!hdr_length) return;
	INFO("%.24s :list masters\n",ctime(&tm));
	while(hdr_length)
	{
		INFO("0x%08x\n",*id);
		hdr_length-=sizeof(uint32_t);
		id++;
	}
}

void w1_message_parser(int s, struct cn_msg *msg)
{
	time_t tm;
	struct w1_netlink_msg *data = (struct w1_netlink_msg *)(msg + 1);
	unsigned int i;
	
	while (msg->len) {
		struct w1_reg_num id;
		
		time(&tm);
		
		INFO("%.24s : %08x.%08x, len=%u, seq=%u, ack=%u, data->len=%u.\n", 
				ctime(&tm), msg->id.idx, msg->id.val, msg->len, msg->seq, msg->ack, data->len);
		
		switch (data->type) {
			case W1_MASTER_ADD:
			case W1_MASTER_REMOVE:
				/*if (data->type == W1_MASTER_ADD)
					w1_test_cmd_master(s, data->id.mst.id);
				*/
				INFO("%.24s : master has been %.8s: id=%08x.\n", 
					ctime(&tm), 
					(data->type == W1_MASTER_ADD)?"added":"removed",
					data->id.mst.id);
				break;
			
			case W1_SLAVE_ADD:
			case W1_SLAVE_REMOVE:
				memcpy(&id, data->id.id, sizeof(id));

				/*if (data->type == W1_SLAVE_ADD)
					w1_test_cmd_slave( s, &id);
				*/
				INFO("%.24s :  slave has been %.8s: id=%02x.%012llx.%02x\n", 
					ctime(&tm), 
					(data->type == W1_SLAVE_ADD)?"added":"removed",
					id.family, (unsigned long long)id.id, id.crc); 
				break;
			case W1_MASTER_CMD:
				w1_msg_master_reply(data);
				break;
			case W1_SLAVE_CMD:
				w1_msg_slave_reply( data);
				break;
			case W1_LIST_MASTERS:
				w1_msg_list_master( data);
				break;
			default:
				INFO("%.24s : type=%02x\n", ctime(&tm), data->type);
				
				for (i=0; i<sizeof(data->id.id); ++i)
					INFO("%02x.", data->id.id[i]);
				INFO( "\n");
		}

		msg->len -= sizeof(struct w1_netlink_msg) + data->len;
		data = (struct w1_netlink_msg *)(((char *)data) + sizeof(struct w1_netlink_msg) + data->len);
	}
}

static int w1_cmd_list_master(int s)
{
	char buf[1024];
	struct w1_netlink_msg *m;
	
	memset(buf, 0, sizeof(buf));

	m = (struct w1_netlink_msg *)buf;
	
	m->type = W1_LIST_MASTERS;
	m->len = 0;
 
	return auth_proto_send_cmd(s,m);
}
#endif



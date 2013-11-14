#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include "auth_proto.h"
#include "auth_log.h"

#define DEFAULT_POLLING_TIMEOUT_MS 100
int auth_proto_send_cmd(int s,struct w1_netlink_msg *msg)
{
    static int send_seq=0;
	struct cn_msg *cmsg;
	struct w1_netlink_msg *m;
	struct nlmsghdr *nlh;
	int size, err;
	
	size = NLMSG_SPACE(sizeof(struct cn_msg) + sizeof(struct w1_netlink_msg) + msg->len);

	nlh = (struct nlmsghdr *)malloc(size);
	if (!nlh)
		return -ENOMEM;
	
	memset(nlh, 0, size);
	
	nlh->nlmsg_seq = send_seq++;
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_type = NLMSG_DONE;
	nlh->nlmsg_len = NLMSG_LENGTH(size - sizeof(struct nlmsghdr));
	nlh->nlmsg_flags = 0;

	cmsg = (struct cn_msg *)NLMSG_DATA(nlh);
	
	cmsg->id.idx = CN_W1_IDX;
	cmsg->id.val = CN_W1_VAL;
	cmsg->seq = nlh->nlmsg_seq;
	cmsg->ack = 0;
	cmsg->len = sizeof(struct w1_netlink_msg) + msg->len;

	m = (struct w1_netlink_msg *)(cmsg + 1);
	memcpy(m, msg, sizeof(struct w1_netlink_msg));
	memcpy(m+1, msg->data, msg->len);
	
	err = send(s, nlh, size, 0);
	if (err == -1) {
		ERROR( "Failed to send: %s [%d].\n", strerror(errno), errno);
		free(nlh);
		return err;
	}
	free(nlh);

	return err;
}

static int auth_proto_create_cmd(struct w1_netlink_msg *m,uint8_t command,uint8_t* data,int8_t length, __u16 maxlen)
{
	char *cmd_data;
	int8_t newlen;
	struct w1_netlink_cmd *cmd;

	cmd_data = (char *)m->data;
	
	newlen = length;

	if (newlen + sizeof(struct w1_netlink_cmd) + m->len > maxlen)
	{
		ERROR("buffer overlayed in %s\n",__func__);
		return 0;
	}

	cmd = (struct w1_netlink_cmd *)cmd_data;

	cmd->cmd = command;
	cmd->len = newlen;
	if(newlen)
		memcpy(cmd->data,data,newlen);

	cmd_data += cmd->len + sizeof(struct w1_netlink_cmd);
	m->len += cmd->len + sizeof(struct w1_netlink_cmd);

	return m->len;
}

int auth_proto_master_cmd(int s, __u32 id,uint8_t cmd,uint8_t* data,int length)
{
	char buf[1024];
	struct w1_netlink_msg *m;

	if(length&&!data) return 0;
	memset(buf, 0, sizeof(buf));

	m = (struct w1_netlink_msg *)buf;
	
	m->type = W1_MASTER_CMD;
	m->len = 0;
	m->id.mst.id = id;

	auth_proto_create_cmd(m,cmd,data,length, sizeof(buf) - sizeof(struct w1_netlink_msg));

	return auth_proto_send_cmd(s, m);
}

int auth_proto_slave_cmd(int s, struct w1_reg_num *id,uint8_t cmd,uint8_t* data,int length)
{
	char buf[1024];
	struct w1_netlink_msg *m;

	if(length&&!data) return 0;
	
	memset(buf, 0, sizeof(buf));

	m = (struct w1_netlink_msg *)buf;
	
	m->type = W1_SLAVE_CMD;
	m->len = 0;
	memcpy(m->id.id, id, sizeof(m->id.id));

	auth_proto_create_cmd(m,cmd,data,length, sizeof(buf) - sizeof(struct w1_netlink_msg));

	

	return auth_proto_send_cmd( s, m);
}


uint8_t auth_proto_crc8(uint8_t * data, int len)
{
    static uint8_t w1_crc8_table[] = {
        0, 94, 188, 226, 97, 63, 221, 131, 194, 156, 126, 32, 163, 253, 31, 65,
        157, 195, 33, 127, 252, 162, 64, 30, 95, 1, 227, 189, 62, 96, 130, 220,
        35, 125, 159, 193, 66, 28, 254, 160, 225, 191, 93, 3, 128, 222, 60, 98,
        190, 224, 2, 92, 223, 129, 99, 61, 124, 34, 192, 158, 29, 67, 161, 255,
        70, 24, 250, 164, 39, 121, 155, 197, 132, 218, 56, 102, 229, 187, 89, 7,
        219, 133, 103, 57, 186, 228, 6, 88, 25, 71, 165, 251, 120, 38, 196, 154,
        101, 59, 217, 135, 4, 90, 184, 230, 167, 249, 27, 69, 198, 152, 122, 36,
        248, 166, 68, 26, 153, 199, 37, 123, 58, 100, 134, 216, 91, 5, 231, 185,
        140, 210, 48, 110, 237, 179, 81, 15, 78, 16, 242, 172, 47, 113, 147, 205,
        17, 79, 173, 243, 112, 46, 204, 146, 211, 141, 111, 49, 178, 236, 14, 80,
        175, 241, 19, 77, 206, 144, 114, 44, 109, 51, 209, 143, 12, 82, 176, 238,
        50, 108, 142, 208, 83, 13, 239, 177, 240, 174, 76, 18, 145, 207, 45, 115,
        202, 148, 118, 40, 171, 245, 23, 73, 8, 86, 180, 234, 105, 55, 213, 139,
        87, 9, 235, 181, 54, 104, 138, 212, 149, 203, 41, 119, 244, 170, 72, 22,
        233, 183, 85, 11, 136, 214, 52, 106, 43, 117, 151, 201, 74, 20, 246, 168,
        116, 42, 200, 150, 21, 75, 169, 247, 182, 232, 10, 84, 215, 137, 107, 53
    };

	uint8_t crc = 0;

	while (len--)
		crc = w1_crc8_table[crc ^ *data++];

	return crc;
}

/*
 * return: >0 more data,0 last data,<0 error
 * 
*/

extern void w1_message_parser(int s, struct cn_msg *msg);

static int auth_proto_polling(int s,char* buf,int32_t buf_length,struct cn_msg **data, int timeout/*ms*/)
{	
	struct pollfd pfd;
	struct nlmsghdr *reply;	
	struct cn_msg *msg;		
	int ret;
	int len;
	pfd.fd = s;
	pfd.events = POLLIN;
	pfd.revents = 0;

	ret = poll(&pfd, 1, timeout);
	if(!ret)
	{
	    //WARN("polling timeout\n");
		return -2;
	}
	else if(-1==ret)
	{
		ERROR("polling error =%d\n",errno);
		return -1;
	}
	else
	{
		len = recv(s, buf, buf_length, 0);
		if (len == -1) {
			ERROR("recv buf\n");
			return -1;
		}
		reply = (struct nlmsghdr *)buf;
		
		switch (reply->nlmsg_type) {
			case NLMSG_ERROR:
				ERROR("Error message received.\n");
				return -3;
			case NLMSG_DONE:
				msg = (struct cn_msg *)NLMSG_DATA(reply);
				//w1_message_parser(s,msg);
				*data = msg;
				return msg->ack;
			default:
				break;
		}
		
		
	}

	return -3;
}
//
//return:
// >0 master count,    ids array contains result
// =0 no master found
// <0 error result
//
int auth_proto_search_masters(int s,uint32_t** ids)
{
	int ret=-1;
	char buf[1024];	
	uint32_t* pids;
	struct w1_netlink_msg *m;
	struct cn_msg *msg;		
	
	memset(buf, 0, sizeof(buf));

	m = (struct w1_netlink_msg *)buf;
	
	m->type = W1_LIST_MASTERS;
	m->len = 0;
 
	ret = auth_proto_send_cmd(s,m);
	if(ret>0)
	{
		ret = 0;
		pids = (uint32_t*)malloc(sizeof(uint32_t)*32);
		if(!pids)
			goto exit;
		//start to recv return result
		while(0<=auth_proto_polling(s,buf,1024,&msg,500)){

			//parse masters
			m = (struct w1_netlink_msg *)(msg + 1);
			while (msg->len) 
			{
				switch(m->type)
				{
					case W1_LIST_MASTERS:
						if((m->len/sizeof(uint32_t)+ret)<=32)
						{
							memcpy(pids+ret*sizeof(uint32_t),m->data,m->len);
							ret+=m->len/sizeof(uint32_t);
						}
						break;
					default:
						break;
				}
				msg->len -= sizeof(struct w1_netlink_msg) + m->len;
				m = (struct w1_netlink_msg *)(((char *)m) + sizeof(struct w1_netlink_msg) + m->len);
			}
		}

		if(ret)
		{
			*ids = pids;
		}
		else
		{
			free(pids);
			*ids=NULL;
		}
	}
exit:
	return ret;
}



//
//return:
// >0 master count ,rns contains result
// =0 no master found
// <0 error result
//
int auth_proto_search_slaves(int s,uint32_t id,struct w1_reg_num** rns)
{
	int ret=-1;
	char buf[1024];	
	struct w1_reg_num* prns;
	struct w1_netlink_msg *m;
	struct cn_msg *msg;		
	
	if(!id) return ret;
	memset(buf, 0, sizeof(buf));
	ret = auth_proto_master_cmd(s,id,W1_CMD_SEARCH,0,0);
	if(ret<0) goto exit;
	ret = 0;
	prns = (struct w1_reg_num*)malloc(sizeof(struct w1_reg_num)*10);
	if(!prns)
		goto exit;
	//start to recv return result
	while(0<=auth_proto_polling(s,buf,1024,&msg,500)){

		//parse masters
		m = (struct w1_netlink_msg *)(msg + 1);
		while (msg->len) 
		{
			switch(m->type)
			{
				case W1_MASTER_CMD:
					{
						struct w1_netlink_cmd *cmd = (struct w1_netlink_cmd *)m->data;
						if(cmd->len)
						{							
							if (cmd->len + sizeof(struct w1_netlink_cmd) > msg->len) {
								WARN("Malformed message.\n");
								break;
							}
							if(W1_CMD_SEARCH == cmd->cmd)
							{
							    int rnc = cmd->len/sizeof(struct w1_reg_num);
                                uint8_t * prn = cmd->data;
                                while(rnc--)
                                {
                                    if(prn[7]==auth_proto_crc8(prn,7))
                                    {
                                        if(ret<10){
                                            memcpy(prns+ret*sizeof(struct w1_reg_num),prn,sizeof(struct w1_reg_num));
                                            ret++;
                                        }
                                    }
                                    prn+=sizeof(struct w1_reg_num);
                                }
							}
						}
					
					}
					break;
				default:
					break;
			}
			msg->len -= sizeof(struct w1_netlink_msg) + m->len;
			m = (struct w1_netlink_msg *)(((char *)m) + sizeof(struct w1_netlink_msg) + m->len);
		}
	}

	if(ret)
	{
		*rns = prns;
	}
	else
	{
		free(prns);
		*rns=NULL;
	}
exit:
	return ret;	
}


//
//reset proto bus
//return:
//0 success
//non-0 fail
//
int auth_proto_reset_bus(int s,uint32_t id)
{
	int ret=-1;
	char buf[1024];	
	struct w1_netlink_msg *m;
	struct cn_msg *msg;		

	if(!id) return ret;
	memset(buf, 0, sizeof(buf));
	ret = auth_proto_master_cmd(s,id,W1_CMD_RESET,0,0);
	if(ret<0) goto exit;
	ret = -1;
	//start to recv return result
	while(0<=auth_proto_polling(s,buf,1024,&msg,DEFAULT_POLLING_TIMEOUT_MS)){

		//parse masters
		m = (struct w1_netlink_msg *)(msg + 1);
		while (msg->len) 
		{
			switch(m->type)
			{
				case W1_MASTER_CMD:
					{
						struct w1_netlink_cmd *cmd = (struct w1_netlink_cmd *)m->data;
						if(W1_CMD_RESET == cmd->cmd)
						{
							ret=0;
						}						
					
					}
					break;
				default:
					break;
			}
			msg->len -= sizeof(struct w1_netlink_msg) + m->len;
			m = (struct w1_netlink_msg *)(((char *)m) + sizeof(struct w1_netlink_msg) + m->len);
		}
	}

exit:
	return ret;		
}


//
//return:
// > 0 return actual read length
// <= 0 read failed 
//
int auth_proto_slave_read(int s,struct w1_reg_num* rn,uint8_t* dat,int length)
{
	int ret=-1;
	char buf[1024]; 
	struct w1_netlink_msg *m;
	struct cn_msg *msg; 	
	memset(buf, 0, sizeof(buf));
	ret = auth_proto_slave_cmd(s,rn,W1_CMD_READ,dat,length);
	if(ret<0) goto exit;
	ret = 0;
	//start to recv return result
	while(0<=auth_proto_polling(s,buf,1024,&msg,DEFAULT_POLLING_TIMEOUT_MS)){

		//parse masters
		m = (struct w1_netlink_msg *)(msg + 1);
		while (msg->len) 
		{
			switch(m->type)
			{
				case W1_SLAVE_CMD:
					{
						struct w1_netlink_cmd *cmd = (struct w1_netlink_cmd *)m->data;
						if(W1_CMD_READ == cmd->cmd)
						{
						    //read opertation should be calculated from msg length
						    int data_len = m->len-sizeof(struct w1_netlink_cmd);
							if((ret+data_len)<=length)
							{
								memcpy(dat+ret,cmd->data,cmd->len);
								ret+=cmd->len;
							}
							
						}						
					
					}
					break;
				default:
					break;
			}
			msg->len -= sizeof(struct w1_netlink_msg) + m->len;
			m = (struct w1_netlink_msg *)(((char *)m) + sizeof(struct w1_netlink_msg) + m->len);
		}
	}

exit:
	return ret; 	
	
}

//
//return:
// > 0 return actual write length
// <= 0 write failed 
//
int auth_proto_slave_write(int s,struct w1_reg_num* rn,uint8_t* dat,int length)
{
	int ret=-1;
	char buf[1024]; 
	struct w1_netlink_msg *m;
	struct cn_msg *msg; 	
	
	memset(buf, 0, sizeof(buf));
	ret = auth_proto_slave_cmd(s,rn,W1_CMD_WRITE,dat,length);
	if(ret<0) goto exit;
	ret = 0;
	//start to recv return result
	while(0<=auth_proto_polling(s,buf,1024,&msg,DEFAULT_POLLING_TIMEOUT_MS)){

		//parse masters
		m = (struct w1_netlink_msg *)(msg + 1);
		while (msg->len) 
		{
			switch(m->type)
			{
				case W1_SLAVE_CMD:
					{
						struct w1_netlink_cmd *cmd = (struct w1_netlink_cmd *)m->data;
						if(W1_CMD_WRITE == cmd->cmd)
						{
						    if(m->status)
							{
							    WARN("write failed\n");
                            }
                            else
                                ret = length;
                            //proto does not support write reply
							//ret+=cmd->len;							
						}						
					
					}
					break;
				default:
					break;
			}
			msg->len -= sizeof(struct w1_netlink_msg) + m->len;
			m = (struct w1_netlink_msg *)(((char *)m) + sizeof(struct w1_netlink_msg) + m->len);
		}
	}

exit:
	return ret; 	
}

//
//return:
// > 0 return actual write length
// <= 0 write failed 
//
int auth_proto_master_write(int s,uint32_t id,uint8_t* dat,int length)
{
	int ret=-1;
	char buf[1024]; 
	struct w1_netlink_msg *m;
	struct cn_msg *msg; 	

	
	if(!id) return ret;
	memset(buf, 0, sizeof(buf));
	ret = auth_proto_master_cmd(s,id,W1_CMD_WRITE,dat,length);
	if(ret<0) goto exit;
	ret = 0;
	//start to recv return result
	while(0<=auth_proto_polling(s,buf,1024,&msg,DEFAULT_POLLING_TIMEOUT_MS)){

		//parse masters
		m = (struct w1_netlink_msg *)(msg + 1);
		while (msg->len) 
		{
			switch(m->type)
			{
				case W1_MASTER_CMD:
					{
						struct w1_netlink_cmd *cmd = (struct w1_netlink_cmd *)m->data;
						if(W1_CMD_WRITE == cmd->cmd)
						{
						    if(m->status)
							{
							    WARN("write failed\n");
                            }
                            else
                                ret = length;
                            //proto does not support write reply
							//ret+=cmd->len;							
						}						
					
					}
					break;
				default:
					break;
			}
			msg->len -= sizeof(struct w1_netlink_msg) + m->len;
			m = (struct w1_netlink_msg *)(((char *)m) + sizeof(struct w1_netlink_msg) + m->len);
		}
	}

exit:
	return ret; 	    
}
//
//return:
// > 0 return actual read length
// <= 0 read failed 
//
int auth_proto_master_read(int s,uint32_t id,uint8_t* dat,int length)
{
	int ret=-1;
	char buf[1024]; 
	struct w1_netlink_msg *m;
	struct cn_msg *msg; 	

	
	if(!id) return ret;
	memset(buf, 0, sizeof(buf));
	ret = auth_proto_master_cmd(s,id,W1_CMD_READ,dat,length);
	if(ret<0) goto exit;
	ret = 0;
	//start to recv return result
	while(0<=auth_proto_polling(s,buf,1024,&msg,DEFAULT_POLLING_TIMEOUT_MS)){

		//parse masters
		m = (struct w1_netlink_msg *)(msg + 1);
		while (msg->len) 
		{
			switch(m->type)
			{
				case W1_MASTER_CMD:
					{
						struct w1_netlink_cmd *cmd = (struct w1_netlink_cmd *)m->data;
						if(W1_CMD_READ == cmd->cmd)
						{
						    //read opertation should be calculated from msg length
						    int data_len = m->len-sizeof(struct w1_netlink_cmd);
							if((ret+data_len)<=length)
							{
								memcpy(dat+ret,cmd->data,cmd->len);
								ret+=cmd->len;
							}
							
						}						
					
					}
					break;
				default:
					break;
			}
			msg->len -= sizeof(struct w1_netlink_msg) + m->len;
			m = (struct w1_netlink_msg *)(((char *)m) + sizeof(struct w1_netlink_msg) + m->len);
		}
	}

exit:
	return ret; 	    
}


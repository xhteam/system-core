#ifndef __AUTH_PROTO_H
#define __AUTH_PROTO_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <asm/byteorder.h>
#include <linux/types.h>
#include "auth_conn.h"

struct w1_reg_num
{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u64	family:8,
		id:48,
		crc:8;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u64	crc:8,
		id:48,
		family:8;
#else
#error "Please fix <asm/byteorder.h>"
#endif
};

enum w1_netlink_message_types {
	W1_SLAVE_ADD = 0,
	W1_SLAVE_REMOVE,
	W1_MASTER_ADD,
	W1_MASTER_REMOVE,
	W1_MASTER_CMD,
	W1_SLAVE_CMD,
	W1_LIST_MASTERS,
};

struct w1_netlink_msg
{
	__u8				type;
	__u8				status;
	__u16				len;
	union {
		__u8			id[8];
		struct w1_mst {
			__u32		id;
			__u32		res;
		} mst;
	} id;
	__u8				data[0];
};

enum w1_commands {
	W1_CMD_READ = 0,
	W1_CMD_WRITE,
	W1_CMD_SEARCH,
	W1_CMD_ALARM_SEARCH,
	W1_CMD_TOUCH,
	W1_CMD_RESET,
	W1_CMD_MAX,
};

struct w1_netlink_cmd
{
	__u8				cmd;
	__u8				res;
	__u16				len;
	__u8				data[0];
};


int auth_proto_send_cmd(int s,struct w1_netlink_msg *msg);
int auth_proto_master_cmd(int s, __u32 id,uint8_t cmd,uint8_t* data,int length);
int auth_proto_slave_cmd(int s, struct w1_reg_num *id,uint8_t cmd,uint8_t* data,int length);



//
//reset proto bus
//return:
//0 success
//non-0 fail
//
int auth_proto_reset_bus(int s,uint32_t id);


//
//return:
// >0 master count,    ids array contains result
// =0 no master found
// <0 error result
//
//caller need to free ids 
int auth_proto_search_masters(int s,uint32_t** ids);



//
//return:
// >0 master count ,rns contains result
// =0 no master found
// <0 error result
//
//caller need to free rns 
int auth_proto_search_slaves(int s,uint32_t id,struct w1_reg_num** rns);


//
//return:
// > 0 return actual read length
// <= 0 read failed 
//
int auth_proto_slave_read(int s,struct w1_reg_num* rn,uint8_t* dat,int length);

//
//return:
// > 0 return actual write length
// <= 0 write failed 
//
int auth_proto_slave_write(int s,struct w1_reg_num* rn,uint8_t* dat,int length);


//
//return:
// > 0 return actual write length
// <= 0 write failed 
//
int auth_proto_master_write(int s,uint32_t id,uint8_t* dat,int length);
//
//return:
// > 0 return actual read length
// <= 0 read failed 
//
int auth_proto_master_read(int s,uint32_t id,uint8_t* dat,int length);

uint8_t auth_proto_crc8(uint8_t * data, int len);

#if defined(__cplusplus)
}
#endif


#endif


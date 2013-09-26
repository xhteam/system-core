#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <cutils/properties.h>

#ifdef LEGACY_UI
#include <openssl/md5.h>
#else
#include "md5.h"
#endif

#include "auth_core.h"
#include "auth_algo.h"
#include "auth_log.h"

//currently only for maxim chip ds28e10
#define AUTH_ALGO_WRITE_CHALLEGE 0x0F
#define AUTH_ALGO_READ_AUTH_PAGE 0xA5


struct auth_algorithm 
{
	uint8_t dev_secret[8];

    //md5
	uint8_t dev_secret_calculated[16];//md5

    //sha
    uint8_t SHAVM_Message[64];
    uint8_t SHAVM_MAC[20];

    //crc16
    uint16_t crc16;
	uint8_t dev_buf[40];


	uint32_t challenge[3];

    uint64_t romid;

	int  (*slave_write)(uint8_t *dat,int length);
	int  (*slave_read)(uint8_t *dat,int length);
	int  (*master_write)(uint8_t *dat,int length);
	int  (*master_read)(uint8_t *dat,int length);
    
};



int auth_algo_init(auth_algorithm_t* algo)
{
	if(algo)
	{
		struct auth_algorithm * algorithm = (struct auth_algorithm *)malloc(sizeof(struct auth_algorithm) );

        //secret for aspen/avenger project
        uint8_t secret_avenger[8]={0x77,0x95,0x69,0x8C,0xA8,0x85,0xA5,0xC1};
        //secret for mmp2 project (reachgood soft)
		uint8_t secret_reachgood[8]={0xE7,0xFD,0xD8,0xF1,0x16,0xEE,0x10,0x34};
        //secret for lop project (G.W & Panasonic)
        uint8_t secret_gwp[8]={0x9c,0x3a,0x5b,0x92,0x66,0xf8,0x35,0x26};
        
        uint8_t* secret;

        //supress compiler warning
        secret = secret_avenger;
        secret = secret_reachgood;
        secret = secret_gwp;
        
        secret = secret_gwp;
            
		if(algorithm)
		{
			*algo = (auth_algorithm_t)algorithm;
		}
		memcpy(algorithm->dev_secret,secret,8*sizeof(uint8_t));

		//set random seed
		struct w1_reg_num reg_num;
        authenticator_get_rn(&reg_num);
		uint8_t* rn = (uint8_t*)&reg_num;
		uint32_t seed = rn[0]+(rn[1]<<8)+(rn[2]<<16)+(rn[3]<<24)+
			rn[4]+(rn[5]<<8)+(rn[6]<<16)+(rn[7]<<24);
		srand(seed);

		algorithm->slave_read = authenticator_slave_read;
		algorithm->slave_write = authenticator_slave_write;
		algorithm->master_read = authenticator_master_read;
		algorithm->master_write = authenticator_master_write;
        
		//TO BE added;
		
		return 0;
	}

	return -1;
}

int auth_algo_dispose(auth_algorithm_t algo)
{
	//TODO
	if(algo)
		free(algo);
	return 0;
}

/*--------------------------------------------------------------------------
 * Calculate a new CRC16 from the input data shorteger.  Return the current
 * CRC16 and also update the global variable CRC16.
 */

static unsigned short docrc16(auth_algorithm_t algo,unsigned short data)
{
   static short oddparity[16] = { 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0 };
   uint16_t CRC16 = algo->crc16;
   data = (data ^ (CRC16 & 0xff)) & 0xff;
   CRC16 >>= 8;

   if (oddparity[data & 0xf] ^ oddparity[data >> 4])
     CRC16 ^= 0xc001;

   data <<= 6;
   CRC16   ^= data;
   data <<= 1;
   CRC16   ^= data;

    algo->crc16 =CRC16;

   return CRC16;
}

//----------------------------------------------------------------------
// computes a SHA given the 64 byte MT digest buffer.  The resulting 5
// long values are stored in the long array, hash.
//
// 'SHAVM_Message' - buffer containing the message digest
// 'SHAVM_Hash'    - result buffer
// 'SHAVM_MAC'     - result buffer, in order for Dallas part
//
static void SHAVM_Compute(auth_algorithm_t algo)
{
    uint8_t* SHAVM_Message = algo->SHAVM_Message;
    uint8_t* SHAVM_MAC = algo->SHAVM_MAC;
    // Hash buffer, in wrong order for Dallas MAC
    unsigned long  SHAVM_Hash[5];
    // MAC buffer, in right order for Dallas MAC
    //unsigned char SHAVM_MAC[20];
    
    unsigned long SHAVM_MTword[80];
    long SHAVM_Temp;
    int SHAVM_cnt;
    
    long SHAVM_KTN[4];
    

   SHAVM_KTN[0]=(long)0x5a827999;
   SHAVM_KTN[1]=(long)0x6ed9eba1;
   SHAVM_KTN[2]=(long)0x8f1bbcdc;
   SHAVM_KTN[3]=(long)0xca62c1d6;   
   for(SHAVM_cnt=0; SHAVM_cnt<16; SHAVM_cnt++)
   {
      SHAVM_MTword[SHAVM_cnt]
         = (((long)SHAVM_Message[SHAVM_cnt*4]&0x00FF) << 24L)
         | (((long)SHAVM_Message[SHAVM_cnt*4+1]&0x00FF) << 16L)
         | (((long)SHAVM_Message[SHAVM_cnt*4+2]&0x00FF) << 8L)
         |  ((long)SHAVM_Message[SHAVM_cnt*4+3]&0x00FF);
   }

   for(; SHAVM_cnt<80; SHAVM_cnt++)
   {
      SHAVM_Temp
         = SHAVM_MTword[SHAVM_cnt-3]  ^ SHAVM_MTword[SHAVM_cnt-8]
         ^ SHAVM_MTword[SHAVM_cnt-14] ^ SHAVM_MTword[SHAVM_cnt-16];
      SHAVM_MTword[SHAVM_cnt]
         = ((SHAVM_Temp << 1) & 0xFFFFFFFE)
         | ((SHAVM_Temp >> 31) & 0x00000001);
   }

   SHAVM_Hash[0] = 0x67452301;
   SHAVM_Hash[1] = 0xEFCDAB89;
   SHAVM_Hash[2] = 0x98BADCFE;
   SHAVM_Hash[3] = 0x10325476;
   SHAVM_Hash[4] = 0xC3D2E1F0;

   for(SHAVM_cnt=0; SHAVM_cnt<80; SHAVM_cnt++)
   {
      SHAVM_Temp
         = ((SHAVM_Hash[0] << 5) & 0xFFFFFFE0)
         | ((SHAVM_Hash[0] >> 27) & 0x0000001F);
      if(SHAVM_cnt<20)
         SHAVM_Temp += ((SHAVM_Hash[1]&SHAVM_Hash[2])|((~SHAVM_Hash[1])&SHAVM_Hash[3]));
      else if(SHAVM_cnt<40)
         SHAVM_Temp += (SHAVM_Hash[1]^SHAVM_Hash[2]^SHAVM_Hash[3]);
      else if(SHAVM_cnt<60)
         SHAVM_Temp += ((SHAVM_Hash[1]&SHAVM_Hash[2])
                       |(SHAVM_Hash[1]&SHAVM_Hash[3])
                       |(SHAVM_Hash[2]&SHAVM_Hash[3]));
      else
         SHAVM_Temp += (SHAVM_Hash[1]^SHAVM_Hash[2]^SHAVM_Hash[3]);
      SHAVM_Temp += SHAVM_Hash[4] + SHAVM_KTN[SHAVM_cnt/20]
                  + SHAVM_MTword[SHAVM_cnt];
      SHAVM_Hash[4] = SHAVM_Hash[3];
      SHAVM_Hash[3] = SHAVM_Hash[2];
      SHAVM_Hash[2]
         = ((SHAVM_Hash[1] << 30) & 0xC0000000)
         | ((SHAVM_Hash[1] >> 2) & 0x3FFFFFFF);
      SHAVM_Hash[1] = SHAVM_Hash[0];
      SHAVM_Hash[0] = SHAVM_Temp;
   }

   //iButtons use LSB first, so we have to turn
   //the result around a little bit.  Instead of
   //result A-B-C-D-E, our result is E-D-C-B-A,
   //where each letter represents four bytes of
   //the result.
   for(SHAVM_cnt=0; SHAVM_cnt<5; SHAVM_cnt++)
   {
      SHAVM_Temp = SHAVM_Hash[4-SHAVM_cnt];
      SHAVM_MAC[((SHAVM_cnt)*4)+0] = (unsigned char)SHAVM_Temp;
      SHAVM_Temp >>= 8;
      SHAVM_MAC[((SHAVM_cnt)*4)+1] = (unsigned char)SHAVM_Temp;
      SHAVM_Temp >>= 8;
      SHAVM_MAC[((SHAVM_cnt)*4)+2] = (unsigned char)SHAVM_Temp;
      SHAVM_Temp >>= 8;
      SHAVM_MAC[((SHAVM_cnt)*4)+3] = (unsigned char)SHAVM_Temp;
   }
   
}


//Compute SHA-1 result
//input parameter: 1. 64-bit unique ROM ID
//                         2. 28-byte user data
//                         3. 12-byte challenge
//                         4. 64-bit secret
static void ComputeSHA1(auth_algorithm_t algo,uint8_t *secret, uint8_t *RomID,
                             uint8_t *data, uint8_t *challenge)
{
    uint8_t* SHAVM_Message = algo->SHAVM_Message;
	// check mandatory input parameters
	if( (secret == NULL) || (RomID == NULL) )
		return;

	// set up message block
	memcpy(SHAVM_Message, secret, 4);
	if(data)
	{
		memcpy(&SHAVM_Message[4], data, 28);
	}
	else
	{
		memset(&SHAVM_Message[4], 0x00, 28);
	}
	if(challenge)
	{
		memcpy(&SHAVM_Message[32], &challenge[8], 4);
		memcpy(&SHAVM_Message[36], challenge, 4);
		SHAVM_Message[40] =challenge[7];
		memcpy(&SHAVM_Message[41], RomID, 7);
		memcpy(&SHAVM_Message[52], &challenge[4], 3);
	}
	else
	{
		memset(&SHAVM_Message[32], 0x00, 4);
		memset(&SHAVM_Message[36], 0xff, 4);
		SHAVM_Message[40]=RomID[0]&0x3f;
		memcpy(&SHAVM_Message[41], &RomID[1], 7);
		memset(&SHAVM_Message[52],0xff, 3);
	}
	memcpy(&SHAVM_Message[48], &secret[4], 4);
	SHAVM_Message[55] = 0x80;
	memset(&SHAVM_Message[56], 0x00, 6);
	SHAVM_Message[62] = 0x01;
	SHAVM_Message[63] = 0xB8;
	
	// perform SHA-1 algorithm, result will be in SHAVM_MAC
	SHAVM_Compute(algo);
	
}

static int write_challenge(auth_algorithm_t algo,uint8_t *challenge,int length)
{
	int i;
	uint8_t* buf=algo->dev_buf;

	if(length>16) return -1;
	if(!algo||!algo->slave_write||!algo->master_read||!algo->master_write) return -2;

    //w1 netlink hacking
    algo->slave_write(buf,0);
    
	buf[0] = AUTH_ALGO_WRITE_CHALLEGE;
	algo->master_write(buf,1);

	algo->master_write(challenge,length);

	for(i=0;i<length;i++) 
	{
		algo->master_read(&buf[i],1);
		if(challenge[i]!=buf[i]) break;
	}

    //dump_data("challenge",challenge,length);
    //dump_data("return challenge",buf,length);
    
	if(i!=length)
	{
		ERROR("challege failed\n");
		return -3;
	}
    
	return 0;
}


static int read_authenticated_page(auth_algorithm_t algo,uint8_t * challenge)
{
	uint8_t* buf=algo->dev_buf;
    uint8_t *secret;
    
	if(!algo||!algo->slave_write||!algo->master_read||!algo->master_write) return -2;
    
    int i,cnt;
    //calculate device real secret
    MD5(algo->dev_secret,8,algo->dev_secret_calculated);

    //this is the real secret for target device
    //dump_data("device secret",algo->dev_secret_calculated,8);

    secret = algo->dev_secret_calculated;
    // compute secret from public key
    ComputeSHA1(algo,secret,(uint8_t*)&algo->romid,NULL,NULL);

    //w1 netlink hacking to do w1_reset_select_slave
    algo->slave_write(buf,0);
    
	// write "read authenticated page" command with target address 0
    //
    cnt=0;
    buf[cnt++]=AUTH_ALGO_READ_AUTH_PAGE;
	buf[cnt++]=0;
	buf[cnt++]=0;
	for(i=0;i<cnt;i++) 
	{
		algo->master_write(&buf[i],1);
	}

	// read 28 bytes data + "FF" + 2 bytes CRC
	for(i = 0;i < 31;i++)
	{
		algo->master_read(&buf[cnt++],1);
	}

	// run the CRC over this part
	algo->crc16 = 0;
	for (i = 0; i < cnt; i++)
	{
		docrc16(algo,buf[i]);
	}
	if( algo->crc16 != 0xB001) //not 0 because that the calculating result is CRC16 and the reading result is inverted CRC16
	{
		memset(algo->SHAVM_MAC,0,20);
		ERROR("read page data failed\n"); 
		return -1; 
	} 


    //calculate the corresponding MAC by the host, device secret reserved in SHAVM_MAC[]
    ComputeSHA1(algo,algo->SHAVM_MAC,(unsigned char *)&algo->romid,&buf[3],challenge);

    // wait for 2 ms
    usleep(5000);

    // read 20 bytes MAC and 2 bytes CRC
    cnt=0;
    for(i = 0;i < 22;i++)
    {
        algo->master_read(&buf[cnt++],1);
    }
    
    // run the CRC over this part MAC
    algo->crc16 = 0;
    for (i = 0; i < cnt; i++)
    {
        docrc16(algo,buf[i]);
    }
    if( algo->crc16 != 0xB001) //not 0 because that the calculating result is CRC16 and the reading result is inverted CRC16
    {
		ERROR("read MAC failed\n"); 
        return -1; 
    } 

    char printbuf[128];
    sprintf(printbuf,"host MAC=");
    for(i=0;i<20;i++)
    {
        sprintf(printbuf+strlen(printbuf),"%02x ",algo->SHAVM_MAC[i]);
    }
    sprintf(printbuf+strlen(printbuf),"\n");
    VERBOSE(printbuf);

    
    //Compare calculated MAC with the MAC from the DS28E10
    for(i=0;i<20;i++)
    {
        if( algo->SHAVM_MAC[i]!=buf[i] )
            break;
    }
    if( i<20 )
    {
        ERROR("authentication FAILURE\n");
        return -1; 
    }
    INFO("authentication PASS\n");

    return 0;
}


int auth_algo_challenge(auth_algorithm_t algo,uint64_t romid)
{
	char value[PROPERTY_VALUE_MAX];    
    property_get("persist.auth.bypass", value, "false");
    if(!strcmp(value,"true"))
	{
        return 0;
	}
    property_get("persist.auth.forcelock", value, "false");
    if(!strcmp(value,"true"))
	{
        return -1;
	}
    

	if(algo)
	{
		uint8_t* challenges = (uint8_t*)algo->challenge;
		algo->challenge[0] = rand();
		algo->challenge[1] = rand();
		algo->challenge[2] = rand();

        algo->romid = romid;

        //reset bus
        if(authenticator_reset_bus(0)<0) goto exit;
        //write challenge
		if(write_challenge(algo,challenges,12)<0) goto exit;
        //check chanllenge
        if(read_authenticated_page(algo,challenges)<0) goto exit;

        return 0;
	}

exit:
	return -1;
}




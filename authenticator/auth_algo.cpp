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

enum{
    //common 
    CMD_READ_ROM                = 0x33,
    CMD_MATCH_ROM               = 0x55,
    CMD_SEARCH_ROM              = 0xf0,
    CMD_SKIP_ROM                = 0xcc,
    CMD_RESUME					= 0xa5,

	//overdrive
	CMD_OVERDRIVE_MATCH_ROM		= 0x69,
	CMD_OVERDRIVE_SKIP_ROM		= 0x3c,
    
    //ds28e10 chip private
    CMD_WRITE_CHALLENGE         = 0x0f,
    CMD_READ_AUTHENTICATED_PAGE = 0xa5,
    CMD_ANONYMOUS_READ          = 0xcc,
//    CMD_ANONYMOUS_WRITE         = 0x,
    CMD_READ_MEMORY             = 0xf0,
    CMD_WRITE_MEMORY            = 0x55,
    CMD_WRITE_SECRET            = 0x5a,
};


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
	int  overdrive;
	int  (*slave_write)(uint8_t *dat,int length);
	int  (*slave_read)(uint8_t *dat,int length);
	int  (*master_write)(uint8_t *dat,int length);
	int  (*master_read)(uint8_t *dat,int length);
    
};

static unsigned short docrc16(auth_algorithm_t algo,unsigned short data);

static int algo_write(auth_algorithm_t algo,uint8_t cmd,uint8_t* buf,int length){
	algo->master_write(&cmd,1);
    if(length>0)
        algo->master_write(buf,length);
    return 0;
}

static int write_int_to_file(const char* file,int v)
{
	int fd = open(file, O_WRONLY );
	if( fd >= 0 ){
		char buf[48];
		int len;
		len=sprintf(buf,"%d\n",v);
		len = write( fd, buf, strlen(buf));
		close(fd);
		if( len > 0 ){
			return 0;
		}
	}else {
		ERROR("failed to open %s\n",file);
	}

	return -1;
}

static void  SwitchToOverdrive(auth_algorithm_t algo,int overdrive)
{
	//switch 1-wire standard mode to overdrive mode
	 if(overdrive){	 	
		write_int_to_file("/sys/module/wire/parameters/overdrive",0);
		 authenticator_reset_bus(0);
		 algo_write(algo,CMD_OVERDRIVE_SKIP_ROM,NULL,0);
		 write_int_to_file("/sys/module/wire/parameters/overdrive",1);
 	}else {
		 //update read/write timing of kernel master driver
		 write_int_to_file("/sys/module/wire/parameters/overdrive",0);
		 authenticator_reset_bus(0);
 		
	}
}

//--------------------------------------------------------------------------
//Issue a power-on reset sequence to DS28E10
// Returns: TRUE (1) success
//          FALSE (0) failed
//
static int  POR(auth_algorithm_t algo)
{
     short i,cnt=0;     
     uint8_t* buf=algo->dev_buf;
	 
	 write_int_to_file("/sys/module/wire/parameters/overdrive",0);

     authenticator_reset_bus(0);
	 
     algo_write(algo,CMD_SKIP_ROM,0,0);
     
     cnt=0;
  // construct a packet to send
     buf[cnt++] = CMD_WRITE_MEMORY; // write memory command
     buf[cnt++] = 0x00; // address LSB
     buf[cnt++] = 0x00;      // address MSB
// data to be written
     for (i = 0; i < 4; i++) buf[cnt++] = 0xff;
// perform the block writing     	
	for(i=0;i<cnt;i++){
		usleep(10000);
	    algo->master_write(&buf[i],1);
	}
// for reading crc bytes from DS28E10
	 
	 usleep(10000);
     algo->master_read(&buf[cnt++],1);

	 usleep(10000);
     algo->master_read(&buf[cnt++],1);
     
     algo->crc16 = 0;
     for (i = 0; i < cnt; i++)
     {
         docrc16(algo,buf[i]);
     }
     
     if( algo->crc16 != 0xB001) //not 0 because that the calculating result is CRC16 and the reading result is inverted CRC16
     {
         ERROR("WriteMemory CRC failed\n"); 
         return -1;
     } 
     usleep(10000);
     buf[0] = 0x00;
     algo->master_write(buf,1);  // clock 0x00 byte as required
     usleep(10000);
	 
     authenticator_reset_bus(0);
	 
     return 0;
}


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

        uint8_t secret_xh[8]={0x91,0x07,0xCF,0xA7,0xD6,0xE3,0x5B,0x44};
        
        uint8_t* secret;

        //supress compiler warning
        secret = secret_avenger;
        secret = secret_reachgood;
        secret = secret_gwp;
        
        secret = secret_xh;
            
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


		/*
        //power on reset??? here
        INFO("reset target\n");
        POR(algorithm);
        	*/
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

    //w1 netlink hacking to do w1_reset_select_slave
    //algo->slave_write(buf,0);        
    authenticator_reset_bus(0);
	algo_write(algo,CMD_SKIP_ROM,NULL,0);
    
	usleep(10000);
	
	buf[0] = CMD_WRITE_CHALLENGE;
	algo->master_write(buf,1);

	//write challenge bytes
	for(i=0;i<length;i++) 
	{
		usleep(1000);
		algo->master_write(&challenge[i],1);
	}

	//read back challenge bytes
	for(i=0;i<length;i++) 
	{
		usleep(1000);
		algo->master_read(&buf[i],1);
	}
	
	for(i=0;i<length;i++) 
	{
		if(challenge[i]!=buf[i]) 
			break;
	}

    
	if(i!=length)
	{
		ERROR("write challenge failed\n");
		dump_data("challenge",challenge,length);
		dump_data("return challenge",buf,length);
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
    //algo->slave_write(buf,0);    
    authenticator_reset_bus(0);
	algo_write(algo,CMD_SKIP_ROM,NULL,0);
    
	// write "read authenticated page" command with target address 0
    //
    cnt=0;
    buf[cnt++]=CMD_READ_AUTHENTICATED_PAGE;
	buf[cnt++]=0;
	buf[cnt++]=0;
	for(i=0;i<cnt;i++) 
	{	
		usleep(1000);
		algo->master_write(&buf[i],1);
	}

	// read 28 bytes data + "FF" + 2 bytes CRC
	for(i = 0;i < 31;i++)
	{	
		usleep(1000);
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
		ERROR("read page data failed(crc failure) crc16[0x%02x]\n",algo->crc16); 
		dump_data("page data",buf,cnt);
		return -1; 
	} 


    //calculate the corresponding MAC by the host, device secret reserved in SHAVM_MAC[]
    ComputeSHA1(algo,algo->SHAVM_MAC,(unsigned char *)&algo->romid,&buf[3],challenge);

    // wait for 20 ms
    usleep(20000);

    // read 20 bytes MAC and 2 bytes CRC
    cnt=0;
    for(i = 0;i < 22;i++)
    {
	    usleep(1000);
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
		ERROR("read mac failed(crc failure) crc16[0x%02x]\n",algo->crc16); 		
		dump_data("mac data",buf,cnt);
        return -1; 
    } 

	if(auth_log_level&AUTHLOG_VERBOSE){
	    char printbuf[128];
	    sprintf(printbuf,"host MAC=");
	    for(i=0;i<20;i++)
	    {
	        sprintf(printbuf+strlen(printbuf),"%02x ",algo->SHAVM_MAC[i]);
	    }
	    sprintf(printbuf+strlen(printbuf),"\n");
	    VERBOSE(printbuf);
	}

    
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
    INFO("\n\n");	
    INFO("!!!PASS!!!");
    INFO("\n\n");	

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
	
	algo->overdrive=0;
	property_get("persist.auth.overdrive", value, "true");
	if(!strcmp(value,"true"))
	{
		algo->overdrive=1;
	}
	if(algo->overdrive){			
		SwitchToOverdrive(algo,algo->overdrive);
	}
    

	if(algo)
	{
		uint8_t* challenges = (uint8_t*)algo->challenge;
		algo->challenge[0] = rand();
		algo->challenge[1] = rand();
		algo->challenge[2] = rand();

        algo->romid = romid;

        //reset bus
        //if(authenticator_reset_bus(0)<0) goto exit;
        //write challenge
		if(write_challenge(algo,challenges,12)<0) goto exit;
        //check chanllenge
        if(read_authenticated_page(algo,challenges)<0) goto exit;

        return 0;
	}

exit:
	return -1;
}




#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>

#include "auth_log.h"
#include "auth_core.h"

#define W1_MASTER_NAME_PREFIX "w1_bus_master"
static int read_int_file( const char* file, int* pResult )
{
    int fd = -1;
    fd = open( file, O_RDONLY );
    if( fd >= 0 ){
        char buf[20];
        int rlt = read( fd, buf, sizeof(buf) );
        if( rlt > 0 ){
            buf[rlt] = '\0';
            *pResult = atoi(buf);
            return 0;
        }
    }
    return -1;
}
static int write_int_file( const char* file, int value )
{
    int fd = -1;
    fd = open( file, O_WRONLY );
    if( fd >= 0 ){
        char buf[20];
        sprintf(buf,"%d\n",value);
        int rlt = write( fd, buf, sizeof(buf) );
        if( rlt > 0 ){
            return 0;
        }
    }
    return -1;
}


int search_masters(uint32_t ids[]) 
{
	int id_count = 0;
	const char *dirname = "/sys/bus/w1/devices";
	char *ptr;
	DIR *dir;
	struct dirent *de;
	dir = opendir(dirname);
	if(dir == NULL)
		return -1;
	while((de = readdir(dir))) {
		if(de->d_name[0] == '.' &&
				(de->d_name[1] == '\0' ||
						(de->d_name[1] == '.' && de->d_name[2] == '\0')))
			continue;
		if(!strncmp(de->d_name,"w1_bus_master",strlen("w1_bus_master")))
		{
			ptr = de->d_name;
			ptr +=strlen("w1_bus_master");
			ids[id_count++] = atoi(ptr);
		}
	}
	closedir(dir);
	return id_count;
}

int search_slaves(uint32_t id,uint8_t family_to_search) 
{
	int count = 0;
	int match_count=0;
	char path[256];
	sprintf(path,"/sys/bus/w1/devices/w1_bus_master%d/w1_master_slave_count",id);
	if(!read_int_file(path,&count))
	{
		INFO("bus %d has %d slave\n",id,count);
	}
	if(count)
	{
		FILE* slaves;
		//now to search all slaves to match family
		sprintf(path,"/sys/bus/w1/devices/w1_bus_master%d/w1_master_slaves",id);
		slaves = fopen(path, "r");
		if (!slaves)
		{
			ERROR("Can't open %s", path);			
		}
		else
		{
			char line[256];
			char family_buffer[16]={0};
			uint8_t family=0;
			while (fgets(line, sizeof(line), slaves))
			{
				INFO("slave:%s\n",line);
				memcpy(family_buffer,line,2);
				family = atoi(family_buffer);
				INFO("family=%#x,search=%#x\n",family,family_to_search);
				if(family==family_to_search)
					match_count++;			
				
			}
			fclose(slaves);
		}
		
	}
	return match_count;
}


int set_master_autosearch(uint32_t id,bool enable)
{
	int ret=0;
	const char *dirname = "/sys/bus/w1/devices";
    char filename[256];
    sprintf(filename,"%s/w1_bus_master%d/w1_master_search",dirname,id);
    //per w1 spec,-1 is search infinite, a small positive integar to disable auto search
    ret =  write_int_file(filename,(true==enable)?-1:1);    

	if(ret){
		sprintf(filename,"%s/w1_bus_master/w1_master_search",dirname);
		//per w1 spec,-1 is search infinite, a small positive integar to disable auto search
		ret =  write_int_file(filename,(true==enable)?-1:1);		
	}	
	if(ret){
		sprintf(filename,"%s/w1 bus master/w1_master_search",dirname);
		//per w1 spec,-1 is search infinite, a small positive integar to disable auto search
		ret =  write_int_file(filename,(true==enable)?-1:1);		
	}

	if(ret){
		ERROR("failed to disable bus %d autosearch\n",id);
	}
	return ret;
}


void dump_data(const char *function,const uint8_t *data ,int size)
{
#define isprint(c)	(c>='!'&&c<='~')
//((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
	char* ptr;
	char digits[2048] = {0};
	int i, j;	
	unsigned char *buf = (unsigned char*)data;
	ALWAYS("%s - length = %d\n",
			   function, size);

	
	for (i=0; i<size; i+=16) 
	{
	  ptr = &digits[0];
	  ptr+=sprintf(ptr,"%06x: ",i);
	  for (j=0; j<16; j++) 
		if (i+j < size)
		 ptr+=sprintf(ptr,"%02x ",buf[i+j]);
		else
		 ptr+=sprintf(ptr,"%s","   ");

	  ptr+=sprintf(ptr,"%s","  ");
		
	  for (j=0; j<16; j++) 
		if (i+j < size)			
			ptr+=sprintf(ptr,"%c",isprint(buf[i+j]) ? buf[i+j] : '.');
	  *ptr='\0';
	  ALWAYS("%s\n",digits);
	}
}


unsigned long simple_strtoul(const char *cp,char **endp,unsigned int base)
{
	unsigned long result = 0,value;

	if (*cp == '0') {
		cp++;
		if ((*cp == 'x') && isxdigit(cp[1])) {
			base = 16;
			cp++;
		}
		if (!base) {
			base = 8;
		}
	}
	if (!base) {
		base = 10;
	}
	while (isxdigit(*cp) && (value = isdigit(*cp) ? *cp-'0' : (islower(*cp)
	    ? toupper(*cp) : *cp)-'A'+10) < base) {
		result = result*base + value;
		cp++;
	}
	if (endp)
		*endp = (char *)cp;
	return result;
}

long simple_strtol(const char *cp,char **endp,unsigned int base)
{
	if(*cp=='-')
		return -simple_strtoul(cp+1,endp,base);
	return simple_strtoul(cp,endp,base);
}

int ustrtoul(const char *cp, char **endp, unsigned int base)
{
	unsigned long result = simple_strtoul(cp, endp, base);
	switch (**endp) {
	case 'G' :
		result *= 1024;
		/* fall through */
	case 'M':
		result *= 1024;
		/* fall through */
	case 'K':
	case 'k':
		result *= 1024;
		if ((*endp)[1] == 'i') {
			if ((*endp)[2] == 'B')
				(*endp) += 3;
			else
				(*endp) += 2;
		}
	}
	return result;
}



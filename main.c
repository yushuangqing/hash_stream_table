#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <endian.h>
#include <getopt.h>
#include "hash.h"


#define POLY 0x01101 // CRC20生成多项式x^20+x^12+x^8+1即:01101 CRC32:04C11DB7L
#define MAC_HEAD 14
#define IP_HEAD 20

bucket_node_ *hash_table[NUMBER];
int index_buket_num[NUMBER]={0};

int packet_num = 0;
static u_int32_t crc_table[256];

int crc_20 = 0;
int add_hash = 0;

void filter_pcap(char *file);//过滤文件中的包
void handle_pcap(char *file);
void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data);
int check_packet_num(bucket_node_ **my_hash);

void find_pcap(char *file);
void find_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data);

unsigned int get_sum_poly(u_int8_t data);
void create_crc_table(void);
int CRC20_key(u_int8_t *data, int len);
  

typedef struct _tcp_hdr  
{  
    u_int16_t sport;    //源端口号   
    u_int16_t dport;    //目的端口号   
    u_int32_t seq_no;        //序列号   
    u_int32_t ack_no;        //确认号   
    #if LITTLE_ENDIAN   
    u_int8_t reserved_1:4; //保留6位中的4位首部长度   
    u_int8_t thl:4;        //tcp头部长度   
    u_int8_t flag:6;       //6位标志   
    u_int8_t reseverd_2:2; //保留6位中的2位   
    #else   
    u_int8_t thl:4;        //tcp头部长度   
    u_int8_t reserved_1:4; //保留6位中的4位首部长度   
    u_int8_t reseverd_2:2; //保留6位中的2位   
    u_int8_t flag:6;       //6位标志    
    #endif   
    u_int16_t wnd_size;    //16位窗口大小   
    u_int16_t chk_sum;     //16位TCP检验和   
    u_int16_t urgt_p;      //16为紧急指针   
}tcphdr; 

typedef struct _udp_hdr  
{  
    u_int16_t sport; //远端口号   
    u_int16_t dport; //目的端口号   
    u_int16_t uhl;      //udp头部长度   
    u_int16_t chk_sum;  //16位udp检验和   
}udphdr;

 
/*
typedef struct info	
{
	int num;
	char *name;
}info_;

int locate(void *data)
{
	info_ *p = data;
	return (p->num)%NUMBER;
}
*/

typedef struct stream_info_	
{
	u_int32_t sip;
	u_int32_t dip;
    u_int16_t sport;
    u_int16_t dport;
    u_int8_t protocol;
	int stream_size;
}stream_info_;

void print(void *data)
{
	stream_info_ *p = data;
    printf("0x%08x, 0x%08x, 0x%04x, 0x%04x, 0x%02x, %d\n", p->sip, p->dip, p->sport, p->dport, p->protocol, p->stream_size);
}

int locate_stream(void *data)
{
	stream_info_ *p = data;
	if(crc_20 == 1)
	{
		return CRC20_key((u_int8_t *)p, sizeof(stream_info_)) % NUMBER;
	}
	if(add_hash == 1)
	{
		return (p->sip + p->sport + p->dip + p->dport + p->protocol) % NUMBER;
	}
}

int compare(void *data1, void *data2)
{
	stream_info_ *p1 = data1;
	stream_info_ *p2 = data2;
	if(p1->sip == p2->sip
			&& p1->sport == p2->sport
			&& p1->dip == p2->dip
			&& p1->dport == p2->dport
			&& p1->protocol == p2->protocol)
	{
		return 1;
	}
	else
		return 0;
}

void update_stream_data(void *data1, void *data2)
{
	stream_info_ *p1 = data1;
	stream_info_ *p2 = data2;
	p1->stream_size += p2->stream_size;
}

void free_data(void *data)
{
	stream_info_ *p = data;
	free(p);
}

int main(int argc, char *argv[])
{
	if (__BYTE_ORDER == __LITTLE_ENDIAN)
	{
		printf("小端\n");
	}
	else
	{
		printf("大端\n");
	}
	int opt;//选项
	while ((opt = getopt(argc, argv, "ca")) != -1)
	{
		switch (opt) 
		{
			case 'c':
				crc_20 = 1;//将带选项的参数字符串转成整数（指定最大传输单元）
				break;
			case 'a':
				add_hash = 1;
				break;
			case '?':
				printf("Unknown option: %c\n",(char)optopt);
				break;
			default :
				printf("输入的非法\n");
				break;
		}
	}
	create_my_hash_bucket(hash_table);
	
	create_crc_table();	
	filter_pcap(argv[optind]);
	handle_pcap("gl_sctp.pcap");
	
	int num = 0;
	for(int i=0; i<NUMBER; i++)
	{
		if(hash_table[i] == NULL)
			num++;
	}
	
	print_hash(hash_table, print);
	
	//for(int i=0; i<NUMBER; i++)
	//{
	//	printf("index %d = %d\n", i, index_buket_num[i]);	
	//}
	
	printf("length of hash table: %d\n", NUMBER);
	printf("length of hash bucket: %d\n", BUCKET_LEN);
	printf("number of packet: %d\n", packet_num);
	printf("number of index: %d\n", NUMBER-num);
	
	
	int cpn = check_packet_num(hash_table);
	printf("check packet num = %d\n", cpn);
	
	
	
	free_hash_bucket(hash_table, free_data);
	
	
	/*
	bucket_node_ *hash_table[NUMBER];
	
	create_my_hash_bucket(hash_table);
	
	info_ arr[6] = {1, "aa", 2, "bb", 3, "cc", 8, "cc", 7, "ee", 12, "ff"};
	
	for(int i=0; i<6; i++)
	{
		insert_hash_bucket(hash_table, &arr[i], locate);
	}
	print_hash(hash_table, print);
	
	delete_hash_bucket(hash_table, &arr[4], locate);
	print_hash(hash_table, print);
	
	free_hash_bucket(hash_table);
	*/
	return 0;
}

void filter_pcap(char *file)//过滤文件中的包
{
	char errbuf[PCAP_ERRBUF_SIZE]={0};
	pcap_t *source_pcap_filter=NULL;
	pcap_dumper_t *pdumper_filter = NULL;
	struct bpf_program filter;
	
	if( NULL==(source_pcap_filter=pcap_open_offline(file, errbuf)) )
	{
		printf("pcap_open_offline() return NULL.\nerrbuf:%s\n", errbuf);
		return ;
	}
	//打开保存的pcap文件	
	if( NULL==(pdumper_filter=pcap_dump_open(source_pcap_filter,"./gl_sctp.pcap")) )
	{
		printf("pcap_dump_open() fail.\n");
		pcap_close(source_pcap_filter);
		return ;
	}
    
    
	pcap_compile(source_pcap_filter, &filter, "(udp or tcp) and ip", 1, 0);
	//pcap_compile(source_pcap_filter, &filter, "sctp", 1, 0);
	pcap_setfilter(source_pcap_filter, &filter);
	
	struct pcap_pkthdr *packet;
	const u_char *pktStr;
	int s = pcap_next_ex(source_pcap_filter, &packet, &pktStr);
	while( s > 0 )
	{
		if( NULL==pktStr )
		{
			printf("pcap_next() return NULL.\n");
			break;		
		}
		else
		{
			//读到的数据包写入生成pcap文件
			pcap_dump((u_char*)pdumper_filter, packet, pktStr);	
		}		
		s = pcap_next_ex(source_pcap_filter, &packet, &pktStr);
		
		packet_num++;
	}

	pcap_close(source_pcap_filter);
	pcap_dump_close(pdumper_filter);
}

void handle_pcap(char *file)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *source_pcap_filter=NULL;
	//打开pcap文件
	if ((source_pcap_filter = pcap_open_offline(file,	   // file_fragment文件描述符或网口句柄
					errbuf					                    // error buffer
					)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file %s.\n", file);
		return ;
	}
	
	pcap_loop(source_pcap_filter, 0, dispatcher_handler, NULL);//处理过滤后的每一个包，dispatcher_handler为回调函数
	pcap_close(source_pcap_filter);
}

void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	const u_char *ip_head_data = pkt_data + MAC_HEAD;
	struct iphdr *ip_head_s = (struct iphdr *)ip_head_data;	
	
	stream_info_ *stream = (stream_info_*)malloc(sizeof(stream_info_));	
	
	stream->sip = htonl(ip_head_s->saddr);	
	stream->dip = htonl(ip_head_s->daddr);	
	stream->protocol = ip_head_s->protocol;
	stream->stream_size = header->len;
	
	if(stream->protocol == 6)
	{
		const u_char *tcp_head_data = pkt_data + MAC_HEAD + IP_HEAD;
		tcphdr *tcp_head_s = (tcphdr *)tcp_head_data;
		stream->sport = htons(tcp_head_s->sport);	
		stream->dport = htons(tcp_head_s->dport);
		
		//printf("tcp_head_s->seq_no = 0x%08x\n", htonl(tcp_head_s->seq_no));
		//printf("tcp_head_s->ack_no = 0x%08x\n", htonl(tcp_head_s->ack_no));
		//printf("tcp_head_s->thl = 0x%x\n", tcp_head_s->thl);
		//printf("tcp_head_s->chk_sum = 0x%04x\n\n", htons(tcp_head_s->chk_sum));
		
	}
	if(stream->protocol == 17)
	{
		const u_char *udp_head_data = pkt_data + MAC_HEAD + IP_HEAD;
		udphdr *udp_head_s = (udphdr *)udp_head_data;
		stream->sport = htons(udp_head_s->sport);	
		stream->dport = htons(udp_head_s->dport);
		
		//printf("udp_head_s->uhl = 0x%04x\n", htons(udp_head_s->uhl));
		//printf("udp_head_s->chk_sum = 0x%04x\n", htons(udp_head_s->chk_sum));
	}
/*			
	if (__BYTE_ORDER == __LITTLE_ENDIAN)
	{
		stream->sport = htons(tcp_head_s->sport);	
		stream->dport = htons(tcp_head_s->dport);
	}
	else
	{
		stream->sport = ((pkt_data[34]<<8) | pkt_data[35]);	
		stream->dport = ((pkt_data[36]<<8) | pkt_data[37]);
	}
*/	
	if((find_key(hash_table, stream, locate_stream, compare, update_stream_data)) >= 0)
	{
		return;
	}
	else
	{
		insert_hash_bucket(hash_table, stream, locate_stream);
	}
		
}

u_int32_t get_sum_poly(u_int8_t data)
{
    u_int32_t sum_poly = data;
    int j;
    sum_poly <<= 24;
    for(j = 0; j < 8; j++)
    {
        int hi = sum_poly&0x80000000; // 取得reg的最高位
        sum_poly <<= 1;
        if(hi) sum_poly = sum_poly^POLY;
    }
    return sum_poly;
}
void create_crc_table(void)  //在使用CRC20_key函数应该先建立crc表
{
    int i;
    for(i = 0; i < 256; i++)
    {
		crc_table[i] = get_sum_poly(i&0xFF);
    }
}

int CRC20_key(u_int8_t * data, int len)
{
    int i;
    u_int32_t reg = 0xFFFFFFFF;// 0xFFFFFFFF，见后面解释
    for(i = 0; i < len; i++)
    {
        reg = (reg<<8) ^ crc_table[(reg>>24)&0xFF ^ data[i]];
    }
    return (reg&0XFFFFF);//得到的reg取后20作为key值 
}

int check_packet_num(bucket_node_ **my_hash)
{
	int num = 0;
	for(int i=0; i<NUMBER; i++)
	{
		bucket_node_ *p = my_hash[i];
		if(p == NULL)
			continue;
		else
		{
			while(p != NULL)
			{
				num += p->packet_num;
				p = p->next;
			}
		}
	}
	return num;
}


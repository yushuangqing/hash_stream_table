#ifndef __HASH_H__
#define __HASH_H__

#define NUMBER 797
#define BUCKET_LEN 10
typedef unsigned int u_int32_t;
typedef unsigned short u_int16_t;
typedef unsigned char u_int8_t;

typedef struct bucket_node	
{
	void * data;
	struct bucket_node *next;
	int packet_num;
}bucket_node_;


void create_my_hash_bucket(bucket_node_ **my_hash);
void print_hash(bucket_node_ **my_hash, void (*print)(void *));
void insert_hash_bucket(bucket_node_ **my_hash, void *data, int (*locate)(void *));
void delete_hash_bucket(bucket_node_ **my_hash, void *data, int (*locate)(void *));
void free_hash_bucket(bucket_node_ **my_hash, void (*free_data)(void *));
int find_key(bucket_node_ **my_hash, void *data, int (*locate)(void *), int (*compare)(void *, void *), void (*update_stream_data)(void *, void *));

#endif
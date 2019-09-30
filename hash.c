#include "hash.h"
#include <stdio.h>
#include <stdlib.h>

extern int index_buket_num[NUMBER];

void create_my_hash_bucket(bucket_node_ **my_hash)
{
	for(int i=0; i<NUMBER; i++)
	{
		my_hash[i] = NULL;
	}	
}

void free_hash_bucket(bucket_node_ **my_hash, void (*free_data)(void *))
{
	for(int i=0; i<NUMBER; ++i)
	{
		if(my_hash[i] == NULL)
		{
			continue;
		}
		else
		{
			bucket_node_ *p = my_hash[i];
			my_hash[i] = NULL;
			while(p != NULL)
			{	bucket_node_ *q = p;
				p = p->next;
				(*free_data)(q->data);
				free(q);
			}
		}
	}
}

void print_hash(bucket_node_ **my_hash, void (*print)(void *))
{
	for(int i=0; i<NUMBER; ++i)
	{
		bucket_node_ *p = my_hash[i];
		if(p == NULL)
			continue;
		else
		{
			while(p != NULL)
			{
				printf("%2d, ", p->packet_num);
				(*print)(p->data);
				p = p->next;
			}
		}	
	}
}


void insert_hash_bucket(bucket_node_ **my_hash, void *data, int (*locate)(void *))
{
	int index = (*locate)(data);
	
	if(index_buket_num[index] >= BUCKET_LEN)
	{
		perror("bucket is full");
		return;
	}
	
	//printf("%d\n", index);
	bucket_node_ *s = (bucket_node_*)malloc(sizeof(bucket_node_));
	
	if(s == NULL)
	{
		perror("malloc bucket_node_");
		return;
	}
	s->data = data;
	s->packet_num = 1;
	s->next = NULL;
	
	if(my_hash[index]== NULL)
	{	
		my_hash[index] = s;
	}
	else
	{
		bucket_node_ *p = my_hash[index];
		while(p->next != NULL)
		{
			p = p->next;
		}
		p->next = s;
	}
	
	(index_buket_num[index])++;
}


void delete_hash_bucket(bucket_node_ **my_hash, void *data, int (*locate)(void *))
{
	int index = (*locate)(data);
	if(my_hash[index] == NULL)
		return;
	bucket_node_ *p = my_hash[index];
	bucket_node_ *q = p->next;
	if(q == NULL)
	{
		if(p->data == data)
		{
			free(p);
			my_hash[index] = NULL;
		}
		return;
	}
	if(q->next == NULL)
	{
		if(p->data == data)
		{
			free(p);
			my_hash[index] = q;
		}
		else if(q->data == data)
		{
			free(q);
			p->next = NULL;
		}
		else
			return;
		return;
	}
	while(q != NULL)
	{	
		if(p == my_hash[index] && p->data == data)
		{
			free(p);
			my_hash[index] = q;
			return;
		}
		else if(q->next == NULL && q->data == data)
		{
			free(q);
			p->next = NULL;
		}
		else if(q->next != NULL && q->data == data)
		{
			 p->next = q->next;
			 free(q);
		}
		else
		{
			p = p->next;
			q = q->next;
		}
	}
}

int find_key(bucket_node_ **my_hash, void *data, int (*locate)(void *), int (*compare)(void *, void *), void (*update_stream_data)(void *, void *))
{
	int index = (*locate)(data);

	bucket_node_ *p = (my_hash[index]);
	while(p != NULL)
	{
		if((*compare)(p->data, data) == 1)
		{
			(p->packet_num)++;
			(*update_stream_data)(p->data, data);
			return index;
		}
		else
		{
			p = p->next;
		}
	}
	return -1;
}




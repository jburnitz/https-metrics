#ifndef QUEUE_H
#define QUEUE_H

#include <time.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include <errno.h>

#include "config.h"

int MSQID = 0;

	
typedef struct datapoint{
	char metricName[METRIC_MAX_LENGTH];
	time_t timeStamp;
} datapoint;

struct message {
        long mtype;
        datapoint dp;
};

void enqueue(const char* metricName, time_t timeStamp){
	struct message msg;
	msg.mtype = 1;
	
	strcpy(msg.dp.metricName, metricName);
	msg.dp.timeStamp = timeStamp;
	
	if (msgsnd(MSQID, &msg, sizeof(datapoint), 0) == -1){
		perror("msgsnd");
	} 
}
datapoint DeQueue(){
	struct message msg;

	if (msgrcv(MSQID, &msg, sizeof(datapoint), 0, 0) == -1){
		perror("msgrcv");
		exit(1);
	}
	return msg.dp;
}
datapoint* DeQueueNonBlock(){
	struct message msg;
	datapoint* dpPtr = (datapoint*)malloc(sizeof(datapoint));
	
        if (msgrcv(MSQID, &msg, sizeof(datapoint), 0, IPC_NOWAIT) == -1){
                if (errno == ENOMSG){
			return NULL;
		} else {
			perror("msgrcv");
	                exit(1);
		}
        }
	memcpy(dpPtr, &msg.dp, sizeof(datapoint));
        return dpPtr;
}


void connectToQueue(){
        //setup the queue
        key_t key;
        
	if ((key = ftok(FTOK_FILE_NAME, FTOK_NUMBER)) == -1){
                perror("ftok");
                exit(1);
        }
        if ((MSQID = msgget(key, 0644 | IPC_CREAT)) == -1){
                perror("msgget");
                exit(1);
        }
}

#endif


#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "queue.h"

#include <sys/shm.h>
#include <sys/ipc.h>
#include <sys/types.h>


int main(){
	connectToQueue();

	char *ptr_getenv;

	// try to use environment variables before deferring to the OS
	// set the environment name
	char environment[ENVIRONMENT_MAX_LENGTH];
	if( (ptr_getenv = getenv(VAR_ENVIRONMENT)) != NULL){
		strcpy(environment, ptr_getenv);
	} else {
		strcpy(environment, DEFAULT_ENVIRONMENT);
	}

	// set the hostname
	char hostname[HOSTNAME_MAX_LENGTH];
        if( (ptr_getenv = getenv(VAR_HOSTNAME)) != NULL){
		strcpy(hostname, ptr_getenv);
        } else if(gethostname(hostname, HOSTNAME_MAX_LENGTH) < 0){
		strcpy(hostname, DEFAULT_HOSTNAME);
	}


	// process the queue
	datapoint *metric;
	int i = 0;
	int metriclen = 0;
	for(;;){
		while((metric = DeQueueNonBlock())){
			metriclen = strlen(metric->metricName) - 1;
			for(i=0; i<metriclen; i++){
				if(metric->metricName[i] == '/')
					metric->metricName[i] = '.';
			}
			if(metric->metricName[i] == '/')
				metric->metricName[i] = '\0';

			printf("%s.%s.%s %lu\n", environment, hostname, metric->metricName, metric->timeStamp);
			free(metric);
		}
	//printf("queue empty...sleeping\n");
	sleep(AGENT_SLEEP_TIME);
	}
	return 0;
}


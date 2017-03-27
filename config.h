#ifndef AGENT_CONFIG_H
#define AGENT_CONFIG_H


#define METRIC_MAX_LENGTH (128)			/* size of metrics being passed betwene the processes balance between performance and truncated data */
#define AGENT_SLEEP_TIME (5)			/* time in seconds agent waits before processing the queue again */

#define HOSTNAME_MAX_LENGTH (128)
#define VAR_HOSTNAME "HOSTNAME"
#define DEFAULT_HOSTNAME "localhost"		/* If we can't determine local hostvia enviroment variable or gethostbyname() use this */ 

#define VAR_ENVIRONMENT "ENVIRONMENT"		/* Name of environment variable to look for defining environment, e.g. export ENVIRONMENT=PROD */
#define DEFAULT_ENVIRONMENT "DEV" 		/* If the environment variable isn't set, what to put instead */
#define ENVIRONMENT_MAX_LENGTH (128)

#define HTTPOUT_STR "httpOut."			/* name representing outbound traffic */
#define HTTPIN_STR "httpIn."			/* name representing inbound traffic */

#define FTOK_FILE_NAME "./agent"		/* known filename to be used in ftok to define a unique queue */
#define FTOK_NUMBER (42)			/* psuedo random number to be concatenated by ftok */


#endif


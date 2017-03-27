#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include <dlfcn.h>

#include <openssl/ssl.h>
#include <gnutls/gnutls.h>

#include "lib/http-parser/http_parser.h"

#include <sys/types.h>
#include <time.h>

#include "config.h"
#include "queue.h"


#ifdef DEBUG
#define DEBUG_PRINT 1
#else
#define DEBUG_PRINT 0
#endif

#define debug_print(...) \
		do { if (DEBUG_PRINT) fprintf(stderr, __VA_ARGS__); } while (0)


static int (*real_SSL_write)(SSL *ssl, const void *buf, int num) = NULL;
static int (*real_SSL_read)(SSL *ssl, void *buf, int num) = NULL;

static ssize_t (*real_gnutls_record_send)(gnutls_session_t session, const void *data, size_t data_size) = NULL;
static ssize_t (*real_gnutls_record_recv)(gnutls_session_t session, void *data, size_t data_size) = NULL;

http_parser *outParser = NULL;
struct http_parser_url urlOutParser;
http_parser_settings parserOutSettings;

http_parser *inParser = NULL;
struct http_parser_url urlInParser;
http_parser_settings parserInSettings;


int handle_parsed_url_out_callback(http_parser *parse, const char *at, size_t length);
int handle_parsed_url_in_callback(http_parser *parse, const char *at, size_t length);

__attribute__((constructor)) void init(){

	// Setting up the http parsers
	outParser = malloc(sizeof(http_parser));
	inParser = malloc(sizeof(http_parser));

	// initializing the generic parsers
        http_parser_init(outParser, HTTP_REQUEST);
	http_parser_init(inParser, HTTP_RESPONSE);

	// defining callbacks
        parserOutSettings.on_url = handle_parsed_url_out_callback;
        parserInSettings.on_url = handle_parsed_url_in_callback;
        
	// initialize URL parser
	http_parser_url_init(&urlOutParser);
	http_parser_url_init(&urlInParser);

	// Connecting to the metric queue
	connectToQueue();

        // Finding the real encryption calls
        // cleaning up old dlerror
        dlerror();
        char* error;
	//
	// Setting up SSL_write
	//
        if (!real_SSL_write){
                real_SSL_write = dlsym(RTLD_NEXT, "SSL_write");
                debug_print("real_SSL_write() addr from: dlsym(\"RTLD_NEXT\", \"SSL_write\") : %p\n", (void*)real_SSL_write);
        }
        if (!real_SSL_write){
                // a fallback case from dlsym()
		// load our own copy
                void *handle;
                handle = dlopen("libssl.so.1", RTLD_LAZY);
                real_SSL_write = dlsym(handle, "SSL_write");
                debug_print("real_SSL_write addr from: dlopen(\"libssl.so.1\", \"SSL_write\") : %p\n", (void*)real_SSL_write);
        }
        if ((error = dlerror()) != NULL){
                // dlopen failed
                fprintf(stderr, "dlerror: %s\n", error);
                //handle this, exit(-1)?
        }
	error = NULL;
        if (!real_SSL_read){
                real_SSL_read = dlsym(RTLD_NEXT, "SSL_read");
                debug_print("real_SSL_read() addr from: dlsym(\"RTLD_NEXT\", \"SSL_read\") : %p\n", (void*)real_SSL_read);
        }

	//
	// Setting up gnutls_record_send
	//
        if (!real_gnutls_record_send){
                real_gnutls_record_send = dlsym(RTLD_NEXT, "gnutls_record_send");
                debug_print("real_gnutls_record_send addr from: dlsym(\"RTLD_NEXT\", \"gnutls_record_send\") : %p\n", (void*)real_gnutls_record_send);
        }
	if (!real_gnutls_record_recv){
		real_gnutls_record_recv = dlsym(RTLD_NEXT, "gnutls_record_recv");
                debug_print("real_gnutls_record_recv addr from: dlsym(\"RTLD_NEXT\", \"gnutls_record_recv\") : %p\n", (void*)real_gnutls_record_recv);
	}
	debug_print("init finished\n");
}
int handle_parsed_url_in_callback(http_parser *parse, const char *at, size_t length){
        /*
        * Parses inbound HTTP calls and reports to queue
        */
	debug_print("PARSING INBOUND");
        http_parser_parse_url(at, length, 0, &urlInParser);

        const char *method = http_method_str(parse->method);
        int methodlen = strlen(method);

        int pathlen,pathoffset;
        pathlen = urlInParser.field_data[UF_PATH].len;
        pathoffset = urlInParser.field_data[UF_PATH].off;

        char metric[METRIC_MAX_LENGTH-1] = {0};

        strcpy(metric, HTTPIN_STR);
        
	// keeping track of string length
	int remaining = METRIC_MAX_LENGTH - sizeof(HTTPIN_STR);

        strncat(metric, method, methodlen);

        remaining -= methodlen;
        if ( pathlen < remaining ){
                remaining = pathlen;
        }
        strncat(metric, at+pathoffset, remaining);

        time_t ts = time(NULL);

        enqueue(metric, ts);
        return 0;
}

int handle_parsed_url_out_callback(http_parser *parse, const char *at, size_t length){
	/*
	* Parses outbound HTTP calls and reports to queue
	*/

        http_parser_parse_url(at, length, 0, &urlOutParser);

	const char *method = http_method_str(parse->method);
	int methodlen = strlen(method);

	int pathlen,pathoffset;
	pathlen = urlOutParser.field_data[UF_PATH].len;
	pathoffset = urlOutParser.field_data[UF_PATH].off;

	char metric[METRIC_MAX_LENGTH-1] = {0};

	strcpy(metric, HTTPOUT_STR);

	// keeping solid track of string length
	int remaining = METRIC_MAX_LENGTH - sizeof(HTTPOUT_STR);

	// adding the HTTP VERB to the metric
	strncat(metric, method, methodlen);	
	
	remaining -= methodlen;
	if ( pathlen < remaining ){
		remaining = pathlen;
	}
	strncat(metric, at+pathoffset, remaining);

	time_t ts = time(NULL);

	enqueue(metric, ts);
        return 0;
}

int SSL_write(SSL *ssl, const void *buf, int num){
	/* 
	* libssl.so encryption handling
	* def provided by openssl/ssl.h
	*
	* known application issues: python2.7 & python3.5 segfaulting, possibly internalized ssl?
	*
	*/	
	debug_print("SSL_write\n");

	size_t nparsed;
	nparsed = http_parser_execute(outParser, &parserOutSettings, buf, num);
	debug_print("characters parsed %zd\n", nparsed);

	return real_SSL_write(ssl, buf, num);
}

int SSL_read(SSL *ssl, void *buf, int num){
	/*
	* libssl.so decryption handling
	* def provided by <openssl/ssl.h>
	*/
	debug_print("SSL_read\n");
	int ret = real_SSL_read(ssl, buf, num);
	if (ret > 0){
	        size_t nparsed;
       		nparsed = http_parser_execute(inParser, &parserInSettings, buf, ret);
	        debug_print("characters parsed %zd\n", nparsed);
	}
	return ret;
}

ssize_t gnutls_record_send(gnutls_session_t session, const void *data, size_t data_size){
	/*
	* libgnutls.so encryption handling
	* defs provided by <gnutls/gnutls.h>
	*
	* known issues: git says "malformed response in ref list"
	*
	*/
        debug_print("gnutls_record_send\n");

        size_t nparsed;
        nparsed = http_parser_execute(outParser, &parserOutSettings, data, data_size);
        debug_print("characters parsed %zd\n", nparsed);

        return real_gnutls_record_send(session, data, data_size);
}
ssize_t gnutls_record_recv(gnutls_session_t session, void *data, size_t data_size){
        /*
        * libgnutls.so decryption handling
        * defs provided by <gnutls/gnutls.h>
        */
	debug_print("gnutls_record_recv");
	
	ssize_t ret = real_gnutls_record_recv(session, data, data_size);
	if (ret > 0){
		size_t nparsed;
                nparsed = http_parser_execute(inParser, &parserInSettings, data, ret);
	        debug_print("characters parsed %zd\n", nparsed);
	}
	return ret;
}


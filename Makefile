CC=gcc
CFLAGS=-Wall -fPIC
LIBFLAGS=-shared -ldl
LIBOUT=libagent.so
AGENTOUT=agent

all: libagent agent

debug: CFLAGS += -DDEBUG
debug: libagent
debug: libagent.o
debug: agent
debug: agent.o

agent: agent.o
	$(CC) agent.o -o agent

agent.o: agent.c
	$(CC) -c agent.c

libagent: libagent.o lib/http-parser/http_parser.o
	$(CC) $(LIBFLAGS) libagent.o lib/http-parser/http_parser.o -o $(LIBOUT)

libagent.o: libagent.c
	$(CC) $(CFLAGS) -c libagent.c

http_parser.o:
	$(MAKE) -C http-parser
			
clean:
	rm -f *o $(LIBOUT) $(AGENTOUT)


OBJS =
OBJS += main.o
OBJS += decap.o
OBJS += decap_erspan.o
OBJS += decap_metamako.o
OBJS += decap_ixia.o
OBJS += decap_arista7150.o
OBJS += decap_arista7280.o
OBJS += decap_exablaze.o

DEF = 
DEF += -O2
DEF += --std=c99 
DEF += -D_LARGEFILE64_SOURCE 
DEF += -D_GNU_SOURCE 

LIBS =
LIBS += -lm

%.o: %.c
	gcc $(DEF) -c -o $@ $<

all: $(OBJS) 
	gcc -O3 -o pcap_decap $(OBJS)  $(LIBS)

clean:
	rm -f $(OBJS)
	rm -f pcap_decap

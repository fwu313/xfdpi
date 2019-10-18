RTE_SDK=/usr/src/dpdk-18.11/x86_64-native-linuxapp-gcc

SOURCEFILES=xftg-distributor.c distributor.c
TARGETNAME=xftg-distributor

LIBS=-L${RTE_SDK}/lib -Wl,--whole-archive,-ldpdk,--no-whole-archive -lrt -lm -ldl -lcrypto -pthread -lnuma -fpic
INCLUDE=-I. -I/usr/include -I${RTE_SDK}/include -I./nDPI/include -I./dpdkframework/include -I./adctimer -I./cjson
DEPS=-Wall -march=native -DALLOW_EXPERIMENTAL_API

ifeq ($(D),1)
OPTIMIZE=-O0
else
OPTIMIZE=-O2
endif

all: distributor ctrl

distributor:
	gcc -g ${OPTIMIZE} ${DEPS} ${INCLUDE} ${LIBS} ${SOURCEFILES} ./nDPI/libndpi.a ./dpdkframework/libdkfw.a -o ${TARGETNAME}

ctrl:
	gcc -g ${OPTIMIZE} ${DEPS} ${INCLUDE} ${LIBS} ./cjson/cJSON.c control.c ./dpdkframework/libdkfw.a -o control

.PHONY: clean

clean:
	rm -f *.o ${TARGETNAME}
	

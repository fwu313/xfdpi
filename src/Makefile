RTE_SDK=/usr/src/dpdk-18.11/x86_64-native-linuxapp-gcc

SOURCEFILES=xfdpi.c dpifunc.c
TARGETNAME=xfdpi

NDPILIB=./nDPI/libndpi.a
DKFWLIB=./dpdkframework/libdkfw.a

LIBS=-L${RTE_SDK}/lib -Wl,--whole-archive,-ldpdk,--no-whole-archive -lrt -lm -ldl -lcrypto -pthread -lnuma -fpic
INCLUDE=-I. -I/usr/include -I${RTE_SDK}/include -I./nDPI/include -I./dpdkframework/include -I./adctimer -I./cjson
DEPS=-Wall -march=native -DALLOW_EXPERIMENTAL_API

ifeq ($(D),1)
OPTIMIZE=-O0
else
OPTIMIZE=-O2
endif

all: dpi ctrl

dpi:
	gcc -g ${OPTIMIZE} ${DEPS} ${INCLUDE} ${LIBS} ${SOURCEFILES} ${NDPILIB} ${DKFWLIB} -o ${TARGETNAME}

ctrl:
	gcc -g ${OPTIMIZE} ${DEPS} ${INCLUDE} ${LIBS} ./cjson/cJSON.c control.c ${DKFWLIB} -o control

.PHONY: clean

clean:
	rm -f *.o ${TARGETNAME}

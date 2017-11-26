CFLAGS = -std=c11 -Wall -Werror

.PHONY: all

all: iphide

siphash.o: SipHash/siphash.c
	${CC} -c -o siphash.o ${CFLAGS} SipHash/siphash.c

iphide: iphide.c siphash.o
	${CC} -o iphide ${CFLAGS} iphide.c siphash.o

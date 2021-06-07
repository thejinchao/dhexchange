#
# Just a make file for the test program
#
# Uncomment appropriate one for the system this is compiling for
OS=LINUX
#OS=CYGWIN

CC=gcc
CFLAGS=-Wall -Wshadow -Wpointer-arith -Wwrite-strings -D ${OS}

#
# Main program
#
OBJS=dhexchange.o 
#test.o
dhtest: test.c ${OBJS}
	${CC} ${CFLAGS} -o dhtest test.c ${OBJS} ${LDFLAGS}

#
# Supporting code
#
dhexchange.o: dhexchange.c dhexchange.h

#
# Clean compiled and temporary files
#
clean:
ifeq (${OS}, CYGWIN)
	rm -f dhtest.exe
else
	rm -f dhtest 
endif
	rm -f *~ *.o

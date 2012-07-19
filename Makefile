# Makefile for gcc compiler for toolchain 4 (SDK Headers)

PROJECTNAME:=pypcap.so
CC=gcc
LD=gcc

OBJS=pypcap.o

LDLIBS= -lpython2.6 -lpcap
all:	$(PROJECTNAME)

$(PROJECTNAME):	$(OBJS)
	$(LD)  -shared -DNDEBUG  $(LDLIBS)  $(filter %.o,$^) -o $@

%.o:	%.m
	$(CC)  -c $(CFLAGS) $< -o $@

%.o:	%.c
	$(CC)   -c $(CFLAGS) $< -o $@

%.o:	%.cpp
	$(CPP)  -c $(CPPFLAGS) $< -o $@

clean:
	rm *.o
	rm $(PROJECTNAME)


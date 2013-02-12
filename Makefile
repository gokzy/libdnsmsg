CC	= clang
CFLAGS	= -Wall -g
OBJS	= main.o 
PROGRAM	= test

all:	$(PROGRAM)

$(PROGRAM):	$(OBJS)
	$(CC)	$(OBJS)	-o $(PROGRAM)

clean:	rm -f *.o *~ $(PROGRAM)

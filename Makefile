CC = gcc

CFLAGS = -c
LDFLAGS = 

LIBS = -lm

OBJS = main.o

%.o: %.c
	$(CC) $(CFLAGS) -o $@ $<

taint-info: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

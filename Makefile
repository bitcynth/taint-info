CC = gcc
RM = rm
RMFLAGS = -f

ifeq ($(OS),Windows_NT)
	RM = del
	RMFLAGS = /F /Q
endif

CFLAGS = -c
LDFLAGS = 

LIBS = -lm

OBJS = main.o

.PHONY: all debug release clean

all: debug

debug: CFLAGS += -g -Og
debug: LDFLAGS += -g -Og
debug: taint-info

release: CFLAGS += -O3 -s
release: LDFLAGS += -O3 -s
release: taint-info

clean:
	-$(RM) $(RMFLAGS) $(OBJS)
	-$(RM) $(RMFLAGS) taint-info.exe
	-$(RM) $(RMFLAGS) taint-info

%.o: %.c
	$(CC) $(CFLAGS) -o $@ $<

taint-info: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

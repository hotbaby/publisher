CC = gcc
CFLAGS = -Werror
LDFLAGS = -lubus \
		  -lubox \
		  -lblobmsg_json \
		  -ljson-c \
		  -lcurl

TARGET = publisher
OBJS += publisher.o

all: $(TARGET)

$(TARGET):$(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

publisher.o:publisher.c
	$(CC) $(CFLAGS) -c publisher.c  -o $@

clean:
	rm $(TARGET) -rf
	rm $(OBJS) -rf

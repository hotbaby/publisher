all: publisher

publisher:
	$(CC) publisher.c -lubus -lubox -lblobmsg_json -ljson-c -lcurl -o $@

clear:
	rm $(TARGET) -rf

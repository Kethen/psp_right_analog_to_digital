OUTPUT=psp-packer
OBJS=main.o
CFLAGS=-Wall -I.
LDFLAGS=-L.
LIBS = -lz

all: $(OUTPUT)

clean:
	rm -f $(OUTPUT) *.o

install:
	cp psp-packer /usr/local/bin/psp-packer

$(OUTPUT): $(OBJS)
	$(LINK.c) $(LDFLAGS) -o $@ $^ $(LIBS)

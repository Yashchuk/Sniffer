
TARGET = sniffer
CFLAGS = -O3 -Wall -c
LIBS = -lpcap
OBJS := ./src/main.o \
./src/snif_list.o \
./src/snif_parser.o \
./src/sniffer.o 

all: $(TARGET)
$(TARGET): $(OBJS)
	@echo 'Building target: $@'
	$(CC) -o $@ $^ $(LIBS)
	@echo 'Finished building target: $@'
	@echo ''
src/%.o: src/%.c
	@echo 'Building file: $<'
	$(CC) $(CFLAGS) -o $@ $^
	@echo 'Finished building: $<'
	@echo ''

.PHONY: clean
clean:
	$(RM) $(OBJS) $(TARGET)





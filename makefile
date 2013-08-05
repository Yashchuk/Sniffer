
RM := rm -rf

OBJS := ./src/main.o \
./src/snif_list.o \
./src/snif_parser.o \
./src/sniffer.o 

LIBS := -lpcap

all: sniffer-1.0.0

sniffer-1.0.0: $(OBJS) $(OBJS)
	@echo 'Building target: $@'
	gcc  -o "sniffer-1.0.0" $(OBJS) $(LIBS)
	@echo 'Finished building target: $@'

src/%.o: src/%.c
	@echo 'Building file: $<'
	gcc -O3 -Wall -c -fmessage-length=0 -o "$@" "$<"
	@echo 'Finished building: $<'

clean:
	-$(RM) $(OBJS) sniffer-1.0.0

.PHONY: all clean dependents




vpath %.c src

.LIBPATTERNS = lib%.a
TARGET = sniffer
CFLAGS = -O3 -Wall -c
LIBS = -lpcap
OBJS := $(patsubst %.c,%.o,$(wildcard src/*.c))

all: $(TARGET)
$(TARGET): $(OBJS) $(LIBS)
	@echo 'Building target: $@'
	$(CC) $^ -o $@
	@echo 'Finished building target: $@'
	@echo ''

.PHONY: clean
clean:
	$(RM) $(OBJS) $(TARGET)


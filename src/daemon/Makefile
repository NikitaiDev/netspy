# Makefile для демона на C

BUILD_DIR ?= ../../build
DAEMON_BUILD_DIR = $(BUILD_DIR)
OBJ_DIR = $(DAEMON_BUILD_DIR)/obj

CC ?= gcc
CFLAGS := -g -O2 -Wall
INCLUDES := -I. -I/usr/include -I/usr/local/include
LDFLAGS := -lelf -lbpf -lpthread

SRCS := $(wildcard *.c)
OBJS := $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRCS))
SKELS := $(wildcard *.skel.h)

TARGET = $(DAEMON_BUILD_DIR)/netspy

.PHONY: all
all: $(TARGET)

$(OBJ_DIR):
	mkdir -p $@

# Зависимость: объектные файлы требуют наличия skel.h
$(OBJ_DIR)/%.o: %.c $(SKELS) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@

.PHONY: clean
clean:
	rm -rf $(OBJ_DIR)
	rm -f $(TARGET)

.PHONY: verify-libbpf
verify-libbpf:
	@if ! pkg-config --exists libbpf; then \
		echo "ERROR: libbpf не найден"; \
		echo "Установите: sudo apt install libbpf-dev"; \
		exit 1; \
	fi
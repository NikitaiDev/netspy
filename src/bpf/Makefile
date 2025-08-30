BUILD_DIR ?= ../../build
BPF_BUILD_DIR = $(BUILD_DIR)/bpf
OBJ_DIR = $(BPF_BUILD_DIR)/obj

KERNEL_VERSION := $(shell uname -r)
KERNEL_HEADERS := /usr/src/linux-headers-$(KERNEL_VERSION)

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= /usr/sbin/bpftool

BPF_CFLAGS := -g -O2 -Wall -target bpf -D__TARGET_ARCH_x86_64
BPF_INCLUDES := -I. -I$(KERNEL_HEADERS)/include -I$(KERNEL_HEADERS)/arch/x86/include

SRCS := $(wildcard *.bpf.c)
OBJS := $(patsubst %.bpf.c,$(OBJ_DIR)/%.bpf.o,$(SRCS))
SKELS := $(patsubst %.bpf.c,../daemon/%.skel.h,$(SRCS))

.PHONY: all
all: $(OBJS) $(SKELS)

$(OBJ_DIR):
	mkdir -p $@

$(OBJ_DIR)/%.bpf.o: %.bpf.c | $(OBJ_DIR)
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -c $< -o $@
	$(LLVM_STRIP) -g $@

../daemon/%.skel.h: $(OBJ_DIR)/%.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

.PHONY: clean
clean:
	rm -rf $(OBJ_DIR)
	rm -f ../daemon/*.skel.h

.PHONY: verify-headers
verify-headers:
	@if [ ! -d "$(KERNEL_HEADERS)" ]; then \
		echo "ERROR: Заголовки ядра не найдены в $(KERNEL_HEADERS)"; \
		echo "INSTALL: sudo apt install linux-headers-$(KERNEL_VERSION)"; \
		exit 1; \
	fi
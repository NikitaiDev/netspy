# Главный Makefile для NetSpy проекта

export BUILD_DIR ?= $(CURDIR)/build
export SRC_DIR = $(CURDIR)/src

.PHONY: all
all: bpf daemon

.PHONY: bpf
bpf:
	$(MAKE) -C $(SRC_DIR)/bpf

.PHONY: daemon
daemon: bpf
	$(MAKE) -C $(SRC_DIR)/daemon

.PHONY: clean
clean:
	$(MAKE) -C $(SRC_DIR)/bpf clean
	$(MAKE) -C $(SRC_DIR)/daemon clean
	rm -rf $(BUILD_DIR)

.PHONY: run
run: all
	sudo $(BUILD_DIR)/netspy

.PHONY: install-deps
install-deps:
	sudo apt update
	sudo apt install -y clang llvm libelf-dev libbpf-dev bpftool \
	linux-headers-$(shell uname -r) gcc-multilib build-essential

.PHONY: verify
verify:
	@echo "=== Проверка инструментов ==="
	@which clang || echo "ERROR: clang не найден"
	@which gcc || echo "ERROR: gcc не найден"
	@which bpftool || echo "ERROR: bpftool не найден"
	@echo "=== Проверка завершена ==="

.PHONY: help
help:
	@echo "Доступные цели:"
	@echo "  all          - Собрать всё (по умолчанию)"
	@echo "  bpf          - Собрать только eBPF часть"
	@echo "  daemon       - Собрать только демон"
	@echo "  run          - Собрать и запустить с sudo"
	@echo "  clean        - Очистить все собранные файлы"
	@echo "  install-deps - Установить зависимости"
	@echo "  verify       - Проверить инструменты"
	@echo "  help         - Показать эту справку"
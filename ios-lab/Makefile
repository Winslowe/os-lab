SHELL := /bin/bash
.DEFAULT_GOAL := help

LABCTL ?= ../labctl
RUNTIME := $(shell if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then echo docker; elif command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then echo podman; fi)
COMPOSE := $(RUNTIME) compose
WEB_PORT ?= 8006
VNC_PORT ?= 5900
FULL ?=
FILE ?=
CONFIRM ?=
PROFILE ?=
INSTALL ?=

.PHONY: help preflight setup prepare up up-gpu boot wait status monitor profiles logs shell web vnc restart update down backup restore install-service uninstall-service reset clean env mac-doctor mac-setup mac-profiles mac-profile mac-sim mac-stop mac-appium mac-appium-stop mac-idb-install mac-idb mac-idb-stop mac-xcuitest mac-status

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@printf '\nRuntime: %s\n' "$(if $(RUNTIME),$(RUNTIME),none - run: sudo make setup)"

preflight: ## Read-only checks: OS, KVM, runtime, ports, disk, RAM, GPU
	bash scripts/preflight.sh

setup: ## Install KVM/Docker and create lab directories (needs sudo)
	sudo bash scripts/setup-ubuntu.sh

prepare: ## Create .env and data directories if missing
	@test -f .env || cp .env.example .env
	@mkdir -p storage shared backups
	@printf 'prepared: .env storage/ shared/ backups/\n'

up: prepare ## Start the macOS container (no wait)
	@if [ -x "$(LABCTL)" ]; then "$(LABCTL)" ios start; else $(COMPOSE) up -d macos; fi

up-gpu: prepare ## Start with Reims vGPU (Intel/AMD, /dev/dri required)
	$(COMPOSE) -f docker-compose.yml -f docker-compose.gpu.yml up -d macos

boot: up wait ## Start and wait for the web viewer

wait: ## Wait for the web viewer
	bash scripts/wait-ready.sh

status: ## Container state, web viewer, ports and storage
	@if [ -x "$(LABCTL)" ]; then "$(LABCTL)" ios status; else \
	  $(COMPOSE) ps; \
	  curl -fsSI --max-time 3 http://127.0.0.1:$(WEB_PORT)/ 2>/dev/null | head -1 || echo "web viewer not responding on :$(WEB_PORT)"; \
	  du -sh storage 2>/dev/null || true; fi

monitor: ## Live dashboard: state, endpoints, CPU/RAM, storage
	../labctl ios monitor

profiles: ## List management profiles (lightweight/development/performance)
	../labctl ios profiles

logs: ## Follow container logs
	$(COMPOSE) logs -f macos

shell: ## Shell inside the QEMU container (debugging)
	$(COMPOSE) exec macos sh

web: ## Print the web viewer URL
	@printf 'web viewer: http://127.0.0.1:%s/\n' "$(WEB_PORT)"

vnc: ## Print the VNC endpoint
	@printf 'VNC: 127.0.0.1:%s (tcp/udp)\n' "$(VNC_PORT)"

restart: ## Recreate the container using the current .env
	@if [ -x "$(LABCTL)" ]; then "$(LABCTL)" ios restart; else $(COMPOSE) down && $(COMPOSE) up -d macos; fi

update: ## Pull the image and recreate the container
	$(COMPOSE) pull macos
	$(COMPOSE) up -d macos

down: ## Stop the container gracefully
	@if [ -x "$(LABCTL)" ]; then "$(LABCTL)" ios stop; else $(COMPOSE) down; fi

backup: ## Archive storage and config into backups/ (FULL=1 adds shared/)
	bash scripts/backup.sh $(if $(filter 1 yes Y,$(FULL)),--full)

restore: ## Restore a backup: make restore FILE=backups/x.tar.gz
	@test -n "$(FILE)" || { echo "usage: make restore FILE=backups/ios-lab-....tar.gz"; exit 1; }
	bash scripts/restore.sh "$(FILE)"

install-service: ## Install a systemd unit that starts ios-lab at boot
	sudo bash scripts/install-service.sh

uninstall-service: ## Remove the systemd unit
	sudo bash scripts/uninstall-service.sh

reset: ## DESTROY the macOS disk (requires CONFIRM=yes)
	@test "$(CONFIRM)" = "yes" || { echo "refusing: run 'make reset CONFIRM=yes' to destroy storage/"; exit 1; }
	-$(COMPOSE) down
	rm -rf storage
	mkdir -p storage
	touch storage/.gitkeep
	@printf 'reset complete: storage/ is empty; next boot reinstalls macOS\n'

clean: ## Remove backups/ only (does not touch storage/)
	find backups -mindepth 1 ! -name .gitkeep -delete
	@printf 'backups/ cleaned\n'

env: ## Show the effective .env
	@cat .env 2>/dev/null || echo "no .env; run: make prepare"

mac-doctor: ## macOS host: check Xcode, simulators, Appium and resources
	bash mac/doctor-mac.sh

mac-setup: ## macOS host: check/install Xcode CLI, Node, Appium and XCUITest
	bash mac/setup-mac.sh $(if $(filter 1 yes Y,$(INSTALL)),--install)

mac-profiles: ## macOS host: list device presets
	bash mac/profile.sh list

mac-profile: ## macOS host: apply a device preset: make mac-profile PROFILE=iphone
	@test -n "$(PROFILE)" || { echo "usage: make mac-profile PROFILE=iphone|ipad|legacy"; exit 1; }
	bash mac/profile.sh use "$(PROFILE)"

mac-sim: ## macOS host: boot the configured Simulator and open Simulator.app
	bash mac/run-simulator.sh

mac-stop: ## macOS host: shut down simulators and the Simulator app
	bash mac/stop-simulator.sh

mac-appium: ## macOS host: start Appium (XCUITest driver)
	bash mac/appium.sh start

mac-appium-stop: ## macOS host: stop Appium
	bash mac/appium.sh stop

mac-idb-install: ## macOS host: install idb companion (Homebrew) and client
	bash mac/idb.sh install

mac-idb: ## macOS host: start an idb companion for the booted simulator
	bash mac/idb.sh start

mac-idb-stop: ## macOS host: stop the idb companion
	bash mac/idb.sh stop

mac-xcuitest: ## macOS host: run one XCUITest session through Appium on the booted simulator
	bash mac/xcuitest.sh smoke

mac-status: ## macOS host: show Xcode, booted simulators and Appium state
	bash mac/status-mac.sh

MANAGER=docker

build:
	$(MANAGER) build -t retrace-server-image -f Dockerfile ../
	$(MANAGER) tag retrace-server-image abrt/retrace-server-image

build_local:
	$(MANAGER) build -t retrace-server-image-local -f Dockerfile_local ../

run:
	$(MANAGER) run --privileged --name retrace-server -dit -p 8181:8181 abrt/retrace-server-image

run_local:
	$(MANAGER) run --privileged --name retrace-server -dit -p 8181:8181 retrace-server-image-local

sh:
	$(MANAGER) exec -it retrace-server bash

del:
	$(MANAGER) rm -f retrace-server

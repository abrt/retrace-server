build:
	docker build -t retrace-server-image -f Dockerfile ../

build_local:
	docker build -t retrace-server-image -f Dockerfile_local ../

run:
	docker run --privileged --name retrace-server -dit -p 8181:8181 retrace-server-image

sh:
	docker exec -it retrace-server bash

del:
	docker rm -f retrace-server

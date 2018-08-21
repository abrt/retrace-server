build:
	docker build -t retrace-server-image -f Dockerfile ../

run:
	docker run --privileged --name retrace-server -dit -p 8181:8181 retrace-server-image

sh:
	docker exec -it retrace-server bash

del:
	docker rm -f retrace-server

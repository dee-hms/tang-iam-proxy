BIN=tang-iam-proxy
ROOT_TARGET=root/usr/bin
BIN_TARGET=$(ROOT_TARGET)/$(BIN)

.PHONY: all bin img clean test

all: bin img
	echo "Building all ..."

bin:
	mkdir -p $(ROOT_TARGET)
	cp generate-signed-certificate.sh $(ROOT_TARGET)
	cp entrypoint.sh $(ROOT_TARGET)
	go build -o $(BIN_TARGET) tang_iam_proxy.go

img:
	podman build -t=quay.io/sec-eng-special/tang-iam-proxy .

clean:
	rm -f $(BIN_TARGET)

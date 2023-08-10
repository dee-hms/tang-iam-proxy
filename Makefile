BIN=tang-iam-proxy
RAW_ROOT_TARGET=root
ROOT_TARGET=$(RAW_ROOT_TARGET)/usr/bin
BIN_TARGET=$(ROOT_TARGET)/$(BIN)
VERSION?=0.0.1
SUB_ALT_NAME?="tang-iam-proxy-passthrough"

.PHONY: all bin cert img clean test

all: bin cert img
	echo "Building all ..."

cert:
	./generate-signed-certificate.sh -s $(SUB_ALT_NAME)
	mkdir -p $(ROOT_TARGET)
	cp server_bundle.pem server.key $(ROOT_TARGET)

bin:
	mkdir -p $(ROOT_TARGET)
	echo "$(VERSION)" > $(RAW_ROOT_TARGET)/version.txt
	cp tang-iam-entrypoint.sh $(ROOT_TARGET)
	cp tang-iam-health-check.sh $(ROOT_TARGET)
	cp tang_bindings.db $(ROOT_TARGET)
	go build -o $(BIN_TARGET) tang_iam_proxy.go

img:
	podman build -t=quay.io/sec-eng-special/tang-iam-proxy-deehms-sqlite:v$(VERSION) .

clean:
	rm -fr $(ROOT_TARGET)
	rm -f $(RAW_ROOT_TARGET)/version.txt


all: bin

.PHONY: bin clean realclean test

bin:
	./build -s

test:
	go test -v ./src

clean realclean:
	-rm -rf bin

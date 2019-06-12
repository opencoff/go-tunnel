
all: bin

.PHONY: bin clean realclean

bin:
	./build -s

clean realclean:
	-rm -rf bin


all: bin

bin: deps
	./build -s

deps:
	./dep.sh sync

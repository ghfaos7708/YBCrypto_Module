all: main.o
	gcc	-o test main.o YBCrypto.dylib

main.o : main.c
	gcc	-c -o main.o main.c

clean:
	rm	*.o	test
all: main.o
	gcc	-o test main.o YBCrypto.so

main.o : main.c
	gcc	-c -o main.o main.c

clean:
	rm	*.o	test
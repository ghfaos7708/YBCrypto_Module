all: blockcipher_cavp.o	ctrdrbg_cavp.o	hash_cavp.o	hmac_cavp.o main.o
	gcc	-o cavp blockcipher_cavp.o	ctrdrbg_cavp.o	hash_cavp.o	hmac_cavp.o main.o YBCrypto.so

blockcipher_cavp.o:	blockcipher_cavp.c
	gcc	-c	-o	blockcipher_cavp.o	blockcipher_cavp.c

ctrdrbg_cavp.o:	ctrdrbg_cavp.c
	gcc	-c	-o	ctrdrbg_cavp.o	ctrdrbg_cavp.c

hash_cavp.o : hash_cavp.c
	gcc	-c	-o	hash_cavp.o	hash_cavp.c

hmac_cavp.o : hmac_cavp.c
	gcc	-c	-o	hmac_cavp.o	hmac_cavp.c

main.o : main.c
	gcc	-c	-o	main.o	main.c

clean:
	rm	*.o	cavp
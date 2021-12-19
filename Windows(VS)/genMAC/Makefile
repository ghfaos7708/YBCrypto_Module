all:	hmac.o	macgen.o	sha256.o	main.o
	gcc	-o	genMac	hmac.o	macgen.o	sha256.o	main.o

hmac.o:	hmac.c
	gcc	-c	-o	hmac.o	hmac.c

macgen.o:	macgen.c
	gcc	-c	-o	macgen.o	macgen.c

sha256.o : sha256.c
	gcc	-c	-o	sha256.o	sha256.c

main.o : main.c
	gcc	-c	-o	main.o	main.c

clean:
	rm	*.o	genMac
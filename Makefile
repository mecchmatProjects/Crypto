default:
	gcc -O3 -c sha256/sha256.c -o sha256.o
	gcc -O3 -c base58/base58.c -o base58.o
	gcc -O3 -c rmd160/rmd160.c -o rmd160.o
	
	gcc -O3 -c util.c -o util.o
	gcc -o mel.exe mel.c util.o sha256.o base58.o rmd160.o -lgmp

search:
	gcc -O3 -c sha256/sha256.c -o sha256.o
	gcc -O3 -c base58/base58.c -o base58.o
	gcc -O3 -c rmd160/rmd160.c -o rmd160.o
	
	gcc -O3 -c util.c -o util.o
	gcc -o search.exe common_key.c util.o sha256.o base58.o rmd160.o 

modmath:
	gcc -o modmath modmath.c -lgmp

keymath:
	gcc -o keymath keymath.c -lgmp

keydivision:
	gcc -O3 -c sha256/sha256.c -o sha256.o
	gcc -O3 -c base58/base58.c -o base58.o
	gcc -O3 -c rmd160/rmd160.c -o rmd160.o
	
	gcc -O3 -c util.c -o util.o
	gcc -o keydivision keydivision.c util.o sha256.o base58.o rmd160.o -lgmp

clean:
	rm -r *.o *.exe 

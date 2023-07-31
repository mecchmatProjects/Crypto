default:
	gcc -O3 -c sha256/sha256.c -o sha256.o
	gcc -O3 -c base58/base58.c -o base58.o
	gcc -O3 -c rmd160/rmd160.c -o rmd160.o
	
	gcc -O3 -c util.c -o util.o
	gcc -o mel mel.c util.o sha256.o base58.o rmd160.o -lgmp

search:
	gcc -O3 -c sha256/sha256.c -o sha256.o
	gcc -O3 -c base58/base58.c -o base58.o
	gcc -O3 -c rmd160/rmd160.c -o rmd160.o
	
	gcc -O3 -c util.c -o util.o
	gcc -o search common_key.c util.o sha256.o base58.o rmd160.o 

clean:
	rm -r *.o search.exe 

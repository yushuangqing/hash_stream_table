table:main.c hash.c hash.h
	gcc -g -o table  main.c hash.c -lpcap 
.PHONY:clean
clean:
	rm table

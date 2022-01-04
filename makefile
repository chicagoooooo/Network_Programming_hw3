all : hw3

hw3 : hw3.c
	gcc -o hw3 hw3.c -lpcap -g
clean : 
	rm -f hw3
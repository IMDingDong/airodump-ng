all: airodump-ng

airodump-ng: airodump-ng.o
	gcc -o airodump-ng airodump-ng.o -lpcap
airodump-ng.o: airodump-ng.h airodump-ng.c
	gcc -c -o airodump-ng.o airodump-ng.c -lpcap

clean:
	rm -f airodump-ng
	rm -f *.o

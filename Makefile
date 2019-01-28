all: airodump-ng

airodump-ng: airodump-ng.o
	gcc -o airodump-ng airodump-ng.o -lpcap -pthread
airodump-ng.o: airodump-ng.h airodump-ng.c
	gcc -c -o airodump-ng.o airodump-ng.c -lpcap -pthread

clean:
	rm -f airodump-ng
	rm -f *.o

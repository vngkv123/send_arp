#Makefile
all: send_arp

send_arp: main.o verification.o utils.o
	g++ -o send_arp main.o verification.o utils.o -Wall -lpcap -lpthread -ggdb
	rm -f *.o
	rm -f *.gch

main.o: packet_struct.h main.cpp
	g++ -c packet_struct.h  main.cpp -std=c++11 -ggdb

verification.o: packet_struct.h verification.cpp
	g++ -c packet_struct.h verification.cpp -std=c++11 -ggdb

utils.o: packet_struct.h utils.cpp
	g++ -c packet_struct.h utils.cpp -std=c++11 -ggdb

clean:
	rm -f *.o
	rm -f send_arp

all: chacha20

chacha20: chacha20.cpp
	g++ chacha20.cpp -o chacha20 -lgmpxx -lgmp
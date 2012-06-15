CC = g++
CFLAGS = -c -Wall
SRC = ./src
BIN = ./bin
OBJ = ./obj

all: ringsign
	@echo "'ringsign' executable created in bin directory.."

ringsign : linkable_ring_signatures.o
	$(CC) $(OBJ)/linkable_ring_signatures.o -lcryptopp -o $(BIN)/ringsign

linkable_ring_signatures.o :
	$(CC) $(CFLAGS) $(SRC)/linkable_ring_signatures.cpp -o $(OBJ)/linkable_ring_signatures.o

clean :	
	rm -rf $(OBJ)/*o $(BIN)/ringsign

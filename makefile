CC := g++
CC_FLAGS := -g -c -Wall -pedantic -Iinclude -DDEBUG=TRUE
CPP_FILES := $(wildcard src/*.cpp)
OBJ_FILES := $(patsubst src/%.cpp, obj/%.o, $(CPP_FILES))
LD_FLAGS := -lcryptopp

ringsign : $(OBJ_FILES)
	$(CC) $(LD_FLAGS) $^ -o $@
	@echo "\nringsign executable created...\n"

obj/%.o : src/%.cpp
	$(CC) $(CC_FLAGS) -c -o $@ $<

clean :	
	rm -rf $(OBJ)/*o ringsign

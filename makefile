CXX = g++
CXXFLAGS = -g -Wall -O3
LFLAGS = -lpcap

all: build/UDP-Statistics

build/UDP-Statistics: src/UDP-Statistics.cpp
	$(CXX) $(CXXFLAGS) -o build/UDP-Statistics src/UDP-Statistics.cpp $(LFLAGS)

run: build/UDP-Statistics
	sudo build/UDP-Statistics
.PHONY: all UDP-Statistics clean

clean:
	$(RM) build/UDP-Statistics

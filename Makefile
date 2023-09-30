CXX = g++
CXXFLAGS = -Wall -std=c++11

TARGET = puzzle
OBJS = puzzle.o Port_scanner.o Port_talker.o ipv4.o knock.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $(TARGET)

port_scanner.o: Port_scanner.cpp Port_scanner.h
	$(CXX) $(CXXFLAGS) -c Port_scanner.cpp

port_talker.o: Port_talker.cpp Port_talker.h
	$(CXX) $(CXXFLAGS) -c Port_talker.cpp

ipv4.o: ipv4.cpp ipv4.h
	$(CXX) $(CXXFLAGS) -c ipv4.cpp

knock.o: knock.cpp knock.h
	$(CXX) $(CXXFLAGS) -c knock.cpp



puzzle.o: puzzle.cpp Port_scanner.h
	$(CXX) $(CXXFLAGS) -c puzzle.cpp

clean:
	rm -f $(OBJS) $(TARGET)
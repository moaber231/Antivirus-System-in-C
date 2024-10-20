# Makefile for Antivirus project

# Compiler to use
CC=gcc -Wno-deprecated-declarations -g 

# Compiler flags
CFLAGS=-I. -Wall 

# Object files
OBJS=Antivirus.o main.o

# Executable name
TARGET=antivirus

# First rule is the one executed when no parameters are fed to the Makefile
all: $(TARGET)

# Rule for linking the final executable
# Depends on the object files
$(TARGET): $(OBJS)
	$(CC) -o $@ $^ -lcrypto -lcurl

# Rule for compiling Antivirus.c to Antivirus.o
# Depends on Antivirus.c and Antivirus.h
Antivirus.o: Antivirus.c Antivirus.h
	$(CC) $(CFLAGS) -c $<

# Rule for compiling main.c to main.o
# Depends on main.c and Antivirus.h
main.o: main.c Antivirus.h
	$(CC) $(CFLAGS) -c $<

# Rule for cleaning up
clean:
	rm -f $(OBJS) $(TARGET)


#compiler
CC = gcc

#compiler flags
#	-g adds debugging info to the executable file
#	-Wall turns on most, but not all, compiler warnings
#	-Werror convert warnings into errors
CFLAGS	= -g -Wall -Werror

#name of executable
TARGET = parsePing
EXECUTABLE = run	#lazy i know

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $(EXECUTABLE) $(TARGET).c

clean:
	$(RM) $(EXECUTABLE)

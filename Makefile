TARGET = keychain_access

CFLAGS    = -pipe -std=c99 -Wall -pedantic -g
SRC_FILES = $(wildcard *.c)
O_FILES   = $(SRC_FILES:%.c=%.o)
LIBS      = -framework Security -framework CoreFoundation


.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(O_FILES)
	gcc $(O_FILES) -o $(TARGET) $(LIBS)

clean:
	rm -f *.o $(TARGET)

run: $(TARGET)
	./$(TARGET)

install:
	@echo No yet implemented.

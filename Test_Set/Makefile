CC = gcc 
CFLAGS = -D INCLUDEMAIN -fno-builtin
INCLUDES = -I ../New_Test_Set/

TARGET = $(target)
SRC = $(wildcard $(target)/*.c)
DIR = $(target)

MAIN = testcase

.PHONY: depend clean

all:    $(MAIN)

$(MAIN): $(SRC) 
	$(CC) $(CFLAGS) $(INCLUDES) io.c $(SRC) -o $(DIR)/$(TARGET) 

clean:
	$(RM) *.o *~ $(MAIN)

depend: $(SRCS)
	makedepend $(INCLUDES) $^

# DO NOT DELETE THIS LINE -- make depend needs it

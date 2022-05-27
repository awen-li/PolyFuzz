

TARGET = driver

CC = gcc
LD = $(CC)

SOURCE_PATH  = source
INCLUDE_PATH = include
OBJ_PATH     = obj

LIBISC_LIBS=lib/libcycloneddsidl.so lib/libddsc.a

CFLAGS     =  -Wunused-result -g -O3 -I$(INCLUDE_PATH) 
LD_CFLAGS  =  $(LIBISC_LIBS) -lpthread -lshmQueue -lxFuzztrace 

SOURCE_FILES = $(wildcard $(SOURCE_PATH)/*.c)
OBJ_FILES     = $(addprefix $(OBJ_PATH)/, $(addsuffix .o,$(notdir $(basename $(SOURCE_FILES)))))

.PHONY:all clean

all: $(TARGET)
$(TARGET): $(OBJ_FILES)
	$(LD) -o $@ $^ $(LD_CFLAGS) 
	
$(OBJ_PATH)/%.o: $(SOURCE_PATH)/%.c
	@if [ ! -d $(OBJ_PATH) ];then mkdir $(OBJ_PATH); fi
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(OBJ_PATH)



TARGET = libJvTrace.so

CC = gcc
LD = $(CC)

SOURCE_PATH  = ./
INCLUDE_PATH = ./
OBJ_PATH     = obj
CTRACER = /usr/include/ctrace
JAVA = /usr/lib/jvm/java-8-openjdk-amd64

CFLAGS     = -fPIC -O3 -I$(INCLUDE_PATH) -I$(CTRACER)/ -I$(JAVA)/include/linux -I$(JAVA)/include
#CFLAGS    = -fPIC -g -I$(INCLUDE_PATH)
LD_CFLAGS  = -fPIC -shared -lpthread -lxFuzztrace

SOURCE_FILES  = $(wildcard $(SOURCE_PATH)/*.c) 
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

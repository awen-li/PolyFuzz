

TARGET = libxFuzztrace.so

CC = clang
LD = $(CC)

AFLPP = ../../AFLplusplus

SOURCE_PATH  = source
INCLUDE_PATH = include
OBJ_PATH     = obj
INSTALL_HEADER = /usr/include/ctrace

#CFLAGS    = -fPIC -O3 -I$(INCLUDE_PATH) -I$(AFLPP)/include
CFLAGS     = -fPIC -g -I$(INCLUDE_PATH) -I$(AFLPP)/include -D__DEBUG__ 
LD_CFLAGS  = -fPIC -shared -lpthread -ldl $(AFLPP)/libAFLDriver.a

$SOURCE_FILES = $(wildcard $(SOURCE_PATH)/*.c)
SOURCE_FILES  = $(wildcard $(SOURCE_PATH)/*.c) #source/Queue.c source/DynTrace.c source/DbCore.c source/List.c
OBJ_FILES     = $(addprefix $(OBJ_PATH)/, $(addsuffix .o,$(notdir $(basename $(SOURCE_FILES)))))

.PHONY:all clean

all: $(TARGET)

$(TARGET): $(OBJ_FILES)
	$(LD) -o $@ $^ $(LD_CFLAGS)
	@cp $(TARGET) -rf /usr/lib/
	@if [ ! -d $(INSTALL_HEADER) ];then mkdir $(INSTALL_HEADER); fi
	@cp $(INCLUDE_PATH)/* -rf $(INSTALL_HEADER)/
	
$(OBJ_PATH)/%.o: $(SOURCE_PATH)/%.c
	@if [ ! -d $(OBJ_PATH) ];then mkdir $(OBJ_PATH); fi
	$(CC) $(CFLAGS) -c -o $@ $<



clean:
	rm -rf $(OBJ_PATH)

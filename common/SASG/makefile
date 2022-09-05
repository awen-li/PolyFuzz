

TARGET = sasg

CC = gcc
LD = $(CC)

SOURCE_PATH  = source
INCLUDE_PATH = include
OBJ_PATH     = obj

#CFLAGS    = -fPIC -O3 -I$(INCLUDE_PATH) 
CFLAGS     = -Wunused-result -fPIC -g -O3 -I$(INCLUDE_PATH) #-D__DEBUG__ 
LD_CFLAGS  = -lm -lpthread -ldl -lshmQueue

SOURCE_FILES = $(wildcard $(SOURCE_PATH)/*.c)
OBJ_FILES     = $(addprefix $(OBJ_PATH)/, $(addsuffix .o,$(notdir $(basename $(SOURCE_FILES)))))

.PHONY:all clean

all: $(TARGET)
$(TARGET): $(OBJ_FILES)
	$(LD) -o $@ $^ $(LD_CFLAGS)
	@cp $(TARGET) -rf /usr/bin/
	@cp include/pl_message.h -rf /usr/include/
	@cd py; ./install.sh; cd -
	
$(OBJ_PATH)/%.o: $(SOURCE_PATH)/%.c
	@if [ ! -d $(OBJ_PATH) ];then mkdir $(OBJ_PATH); fi
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(OBJ_PATH)

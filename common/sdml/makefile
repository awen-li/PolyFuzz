

TARGET = sdml

export SDML_PATH = $(PWD)

export CC = clang
export LD = $(CC)

export SOURCE_PATH  = $(SDML_PATH)/source
export INCLUDE_PATH = $(SDML_PATH)/include
export LIB_PATH     = $(SDML_PATH)/lib

OBJ_PATH     = obj

#export CFLAGS    = -fPIC -O3 -I$(INCLUDE_PATH) 
export CFLAGS     = -fPIC -g -I$(INCLUDE_PATH) -D__DEBUG__ 
export LD_CFLAGS  = -lpthread -ldl

SOURCE_FILES = $(wildcard $(SOURCE_PATH)/*.c)
OBJ_FILES     = $(addprefix $(OBJ_PATH)/, $(addsuffix .o,$(notdir $(basename $(SOURCE_FILES)))))

MUTATORS = source 

.PHONY:all clean

all: $(TARGET)

$(TARGET): $(OBJ_FILES)
	$(LD) -o $@ $^ $(LD_CFLAGS)
	@cp $(TARGET) -rf /usr/bin/
	@make -C ./source clean
	@make -C ./source
	
$(OBJ_PATH)/%.o: $(SOURCE_PATH)/%.c
	@if [ ! -d $(OBJ_PATH) ];then mkdir $(OBJ_PATH); fi
	$(CC) $(CFLAGS) -c -o $@ $<



clean:
	rm -rf $(OBJ_PATH)

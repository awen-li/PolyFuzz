
CC = clang 
LD = clang

SOURCE_PATH  = source
INCLUDE_PATH = include
PYTHON       = /usr/lib/anaconda3

OBJ_PATH     = obj

#-emit-llvm
CFLAGS       = -O2 -g -I$(INCLUDE_PATH) -I$(PYTHON)/include/python3.7m
LD_CFLAGS    = -flto -L$(PYTHON)/lib -lpython3.7m



SOURCE_FILES = $(wildcard $(SOURCE_PATH)/*.c)
OBJ_FILES    = $(addprefix $(OBJ_PATH)/, $(addsuffix .o,$(notdir $(basename $(SOURCE_FILES)))))

TARGET = pyins

.PHONY:all clean

all: $(TARGET)

$(TARGET): $(OBJ_FILES)
	$(LD) -o $@ $^ $(LD_CFLAGS)
	
$(OBJ_PATH)/%.o: $(SOURCE_PATH)/%.c
	@if [ ! -d $(OBJ_PATH) ];then mkdir $(OBJ_PATH); fi
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(OBJ_PATH) $(TARGET)

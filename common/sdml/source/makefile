SOURCE_DIR = mutators
HEADER_DIR = mutators

CUR_INCLUDES = $(INCLUDE_PATH) -I$(HEADER_DIR)
CUR_CFLAGS = $(CFLAGS) -fpic

SOURCE_FILES = $(wildcard $(SOURCE_DIR)/*.c)
OBJ_FILES = $(addprefix $(OBJ_PATH)/, $(addsuffix .o,$(notdir $(basename $(SOURCE_FILES)))))

TARGET = $(LIB_PATH)/libmutators.so

.PHONY:all clean

all: $(TARGET)

$(TARGET): $(OBJ_FILES)
	@if [ ! -d $(LIB_PATH) ];then mkdir $(LIB_PATH); fi
	$(LD) -shared -o $@ $^
	
$(OBJ_PATH)/%.o: $(SOURCE_DIR)/%.c
	@if [ ! -d $(OBJ_PATH) ];then mkdir $(OBJ_PATH); fi
	$(CC) $(CUR_CFLAGS) -o $@ $(CUR_INCLUDES) -c $<

clean:
	rm -rf $(OBJ_PATH) $(TARGET)
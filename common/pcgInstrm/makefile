

TARGET = libpcgInstrm.so

CC = clang
LD = $(CC)

SOURCE_PATH  = source
INCLUDE_PATH = include
OBJ_PATH     = obj
INSTALL_HEADER = /usr/include/pcgInstrm

CFLAGS     = -fPIC -O3 -I$(INCLUDE_PATH) 
LD_CFLAGS  = -fPIC -shared

SOURCE_FILES  = $(wildcard $(SOURCE_PATH)/*.cpp)
OBJ_FILES     = $(addprefix $(OBJ_PATH)/, $(addsuffix .o,$(notdir $(basename $(SOURCE_FILES)))))

.PHONY:all clean

all: $(TARGET)

$(TARGET): $(OBJ_FILES)
	$(LD) -o $@ $^ $(LD_CFLAGS)
	@cp $(TARGET) -rf /usr/lib/
	@if [ ! -d $(INSTALL_HEADER) ];then mkdir $(INSTALL_HEADER); fi
	@cp $(INCLUDE_PATH)/pcgInstrm* -rf $(INSTALL_HEADER)/
	
$(OBJ_PATH)/%.o: $(SOURCE_PATH)/%.cpp
	@if [ ! -d $(OBJ_PATH) ];then mkdir $(OBJ_PATH); fi
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(OBJ_PATH)

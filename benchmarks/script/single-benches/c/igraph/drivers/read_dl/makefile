

TARGET = driver

CC = g++
LD = $(CC)

SOURCE_PATH  = source
INCLUDE_PATH = include
OBJ_PATH     = obj

LIBISC_LIBS=lib/libigraph.a

CFLAGS     =  -Wunused-result -g -O3 -I$(INCLUDE_PATH) -I$(INCLUDE_PATH)/igraph
LD_CFLAGS  =  $(LIBISC_LIBS) -lpthread -lshmQueue -lxFuzztrace 

SOURCE_FILES = $(wildcard $(SOURCE_PATH)/*.cpp)
OBJ_FILES     = $(addprefix $(OBJ_PATH)/, $(addsuffix .o,$(notdir $(basename $(SOURCE_FILES)))))

.PHONY:all clean

all: $(TARGET)
$(TARGET): $(OBJ_FILES)
	$(LD) -o $@ $^ $(LD_CFLAGS) 
	
$(OBJ_PATH)/%.o: $(SOURCE_PATH)/%.cpp
	@if [ ! -d $(OBJ_PATH) ];then mkdir $(OBJ_PATH); fi
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(OBJ_PATH)

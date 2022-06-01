
include Makefile.common

TARGET = libjansi.so
OBJ_PATH = obj

.phony: all clean

all: $(TARGET)

CCFLAGS:= $(CCFLAGS) -fPIC 

$(OBJ_PATH)/%.o: src/main/native/%.c
	@mkdir -p $(@D)
	$(info running: $(CC) $(CCFLAGS) -c $< -o $@)
	$(CC) $(CCFLAGS) -c $< -o $@

$(TARGET): $(OBJ_PATH)/jansi.o $(OBJ_PATH)/jansi_isatty.o $(OBJ_PATH)/jansi_structs.o $(OBJ_PATH)/jansi_ttyname.o
	@mkdir -p $(@D)
	$(CC) $(CCFLAGS) -o $@ $(OBJ_PATH)/jansi.o $(OBJ_PATH)/jansi_isatty.o $(OBJ_PATH)/jansi_structs.o $(OBJ_PATH)/jansi_ttyname.o -shared
	@cp libjansi.so ./src/main/resources/org/fusesource/jansi/internal/native/Linux/x86_64/ -f 

clean:
	rm -rf $(TARGET)
	rm -rf $(OBJ_PATH)

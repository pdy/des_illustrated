print-%  : ; @echo $* = $($*)

CC := clang

FLAGS := -std=c99

LD_FLAGS := #-L

LD_LIBS := -pthread

INCLUDES :=  

BUILD = ./bin/release
CCFLAGS = $(FLAGS) $(INCLUDES) -O3 -Wall
STRIP := strip
ifneq (, $(findstring debug,$(MAKECMDGOALS)))
	BUILD = ./bin/debug
	CCFLAGS = $(FLAGS) $(INCLUDES) -g -Weverything
	STRIP = echo
endif

.PHONY: all clean

all: post-build
debug: all
release: all

pre-build:
	@mkdir -p $(BUILD) # prep dist 

post-build: main-build
	$(STRIP) $(BUILD)/*

main-build: pre-build
	@$(MAKE) --no-print-directory $(BUILD)/des
	@$(MAKE) --no-print-directory $(BUILD)/des_create_example_data
	
clean:
	@rm -r ./bin


$(BUILD)/%: ./%.c
	@$(CC) $(CCFLAGS) -o $@ $^ $(LD_FLAGS) $(LD_LIBS)
	@echo "$@"

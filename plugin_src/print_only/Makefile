TOOLCHAIN     := $(OO_PS4_TOOLCHAIN)
PROJDIR       := source
INTDIR        := build
TARGET        := $(notdir $(CURDIR)).prx

LIBS          := -lc -lc++ -lSceLibcInternal -lkernel \
                 -lSceSysmodule -lMinhook -L$(GOLDHEN_SDK) -lGoldHEN_Hook

CFILES        := $(wildcard $(PROJDIR)/*.c)
CPPFILES      := $(wildcard $(PROJDIR)/*.cpp)
OBJS          := $(patsubst $(PROJDIR)/%.c, $(INTDIR)/%.o, $(CFILES)) \
                 $(patsubst $(PROJDIR)/%.cpp, $(INTDIR)/%.o, $(CPPFILES))

CFLAGS        := --target=x86_64-pc-freebsd12-elf -fPIC -funwind-tables -c \
		-mstackrealign \
                 $(EXTRAFLAGS) -isysroot $(TOOLCHAIN) -isystem $(TOOLCHAIN)/include \
                 -I../../common -I$(GOLDHEN_SDK)/include -std=c11 -D_DEFAULT_SOURCE -DFMT_HEADER_ONLY -mstackrealign

CXXFLAGS      := $(CFLAGS) -isystem $(TOOLCHAIN)/include/c++/v1 \
                 -std=c++11 -DFMT_HEADER_ONLY 
GOLDHEN_SDK   := /home/ryan/code/ps4/GoldHEN_Plugins_SDK
LDFLAGS       := -m elf_x86_64 -pie --script $(TOOLCHAIN)/link.x --eh-frame-hdr \
                 -L$(TOOLCHAIN)/lib $(LIBS) $(GOLDHEN_SDK)/build/crtprx.o

$(TARGET): $(INTDIR) $(OBJS)
	$(LD) $(OBJS) -o $(INTDIR)/$(PROJDIR).elf $(LDFLAGS) -e _init
	$(TOOLCHAIN)/bin/$(CDIR)/create-fself -in=$(INTDIR)/$(PROJDIR).elf \
	-out=$(INTDIR)/$(PROJDIR).oelf --lib=$(TARGET) --paid 0x3800000000000011

$(INTDIR)/%.o: $(PROJDIR)/%.c
	$(CC) $(CFLAGS) -o $@ $<

$(INTDIR)/%.o: $(PROJDIR)/%.cpp
	$(CCX) $(CXXFLAGS) -o $@ $<

$(INTDIR)/%.o: $(COMMONDIR)/%.cpp
	$(CCX) $(CXXFLAGS) -o $@ $<

_unused      := $(shell mkdir -p $(INTDIR))
UNAME_S      := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
	CC := clang
	CCX := clang++
	LD := ld.lld
	CDIR := linux
	ASMLR := as
endif

ifeq ($(UNAME_S),Darwin)
	CC := /usr/local/opt/llvm/bin/clang
	CCX := /usr/local/opt/llvm/bin/clang++
	LD := /usr/local/opt/llvm/bin/ld.lld
	CDIR := macos
	ASMLR := as
endif

.PHONY: clean all

.DEFAULT_GOAL := all

clean:
	rm -f $(INTDIR)/$(PROJDIR).oelf $(OBJS) \
	$(TARGET) $(INTDIR)/$(PROJDIR).elf

target: $(TARGET)

all: clean target

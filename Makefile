VERSION := 1.0.0

LIBS := -ljansson -lcurl -lzip

CC      :=  gcc
CFLAGS  := -Wall -Wextra -Wno-unused-parameter
LDFLAGS := -lm $(LIBS)

BUILDDIR := build
SOURCEDIR := src
HEADERDIR := src

NAME := npi
BINARY := npi

RM := rm -rf
MKDIR := mkdir

ifeq ($(OS),Windows_NT)
	ifeq ($(ARCH), ARM64)
		CC = arm-none-eabi-gcc
	else
		CC = gcc
		CFLAGS += -DWINDOWS
		LDFLAGS += -lws2_32 -lShlwapi 
	endif
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		AR=gcc-ar
		CFLAGS += -DLINUX -D_XOPEN_SOURCE=700 -D_GNU_SOURCE 
		LDFLAGS += -Wl,-rpath=./ -lpthread -pthread
	endif
	ifeq ($(UNAME_S),Darwin)
		AR=ar
		CFLAGS += -DDARWIN
	endif
	CFLAGS += -fPIC
	LDFLAGS += -ldl
endif

DEBUG ?= 0
ifeq ($(DEBUG),0)
	CFLAGS += -O2 -DNDEBUG
else
	CFLAGS += -g -DDEBUG
endif

ifeq ($(USE_MALLOC)),1)
	CFLAGS += -DUSE_MALLOC
endif

SOURCES := $(shell find $(SOURCEDIR) -name '*.c')
OBJECTS := $(addprefix $(BUILDDIR)/,$(SOURCES:$(SOURCEDIR)/%.c=%.o))

$(BINARY): $(OBJECTS)
	@mkdir -p $(@D)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)
	@echo CC LINK $@

$(BUILDDIR)/%.o: $(SOURCEDIR)/%.c
	@mkdir -p $(@D)
	@$(CC) $(CFLAGS) -I $(HEADERDIR) -I $(dir $<) -c $< -o $@
	@echo CC $<

all: $(BINARY)

clean: 
	$(RM) $(BINARY) $(OBJECTS)

setup: 
	$(MKDIR) -p $(BUILDDIR)

.PHONY: all clean
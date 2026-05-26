#/**
#* MIT License
#*
#* Copyright (c) 2020 Infineon Technologies AG
#*
#* Permission is hereby granted, free of charge, to any person obtaining a copy
#* of this software and associated documentation files (the "Software"), to deal
#* in the Software without restriction, including without limitation the rights
#* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#* copies of the Software, and to permit persons to whom the Software is
#* furnished to do so, subject to the following conditions:
#*
#* The above copyright notice and this permission notice shall be included in all
#* copies or substantial portions of the Software.
#*
#* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#* SOFTWARE
#
#*/


TRUSTM = trustm_lib

.DEFAULT_GOAL := all
# Select which mbedTLS tree to compile from trustm_lib/external/
# Usage: make MBEDTLS_VARIANT=4
MBEDTLS_VARIANT ?= 4

ifeq ($(MBEDTLS_VARIANT),4)
MBEDTLS_DIR := $(TRUSTM)/external/mbedtls-4.x
MBEDTLS_CONFIG := $(TRUSTM)/config/mbedtls_4.x_default_config.h
MBEDTLS_INSTALL_DIR := $(MBEDTLS_DIR)/install
MBEDTLS_LIB := $(MBEDTLS_INSTALL_DIR)/lib/libmbedtls.a
else ifeq ($(MBEDTLS_VARIANT),3)
MBEDTLS_DIR := $(TRUSTM)/external/mbedtls-3.x
MBEDTLS_CONFIG := $(TRUSTM)/config/mbedtls_3.x_default_config.h
MBEDTLS_INSTALL_DIR := $(MBEDTLS_DIR)/install
MBEDTLS_LIB := $(MBEDTLS_INSTALL_DIR)/lib/libmbedtls.a
else
MBEDTLS_DIR := $(TRUSTM)/external/mbedtls
MBEDTLS_CONFIG := $(TRUSTM)/config/mbedtls_default_config.h
endif

BUILD_FOR_ULTRA96 = NO
USE_LIBGPIOD_RPI = YES

PALDIR =  $(TRUSTM)/extras/pal/linux
LIBDIR = $(TRUSTM)/src/util
LIBDIR += $(TRUSTM)/src/crypt
LIBDIR += $(TRUSTM)/src/comms
LIBDIR += $(TRUSTM)/src/common
LIBDIR += $(TRUSTM)/src/cmd
ifeq ($(MBEDTLS_VARIANT),2)
  LIBDIR += $(MBEDTLS_DIR)/library
endif

MBEDTLS_BUILD_DIR ?= $(MBEDTLS_DIR)/build-install

ifneq (,$(filter $(MBEDTLS_VARIANT),3 4))
  MBEDTLS_INSTALL_DIR := $(MBEDTLS_DIR)/install
  LDFLAGS += -L$(MBEDTLS_INSTALL_DIR)/lib
  LDFLAGS += -lmbedtls -lmbedx509
endif
ifeq ($(MBEDTLS_VARIANT),4)
  LDFLAGS += -lmbedcrypto
endif
ifeq ($(MBEDTLS_VARIANT),3)
  LDFLAGS += -ltfpsacrypto
endif
LIBDIR += trustm_helper

ARCH := $(shell dpkg --print-architecture)
BINDIR = bin
APPDIR = ex_cli_applications
PROVDIR = trustm_provider
ifeq ($(ARCH), arm64)
LIB_INSTALL_DIR = /usr/lib/aarch64-linux-gnu
else
LIB_INSTALL_DIR = /usr/lib/arm-linux-gnueabihf
endif
PROVIDER_INSTALL_DIR = $(LIB_INSTALL_DIR)/ossl-modules

INCDIR = $(TRUSTM)/include
INCDIR += $(TRUSTM)/include/ifx_i2c
INCDIR += $(TRUSTM)/include/comms
INCDIR += $(TRUSTM)/include/common
INCDIR += $(TRUSTM)/include/cmd
INCDIR += $(TRUSTM)/include/pal
INCDIR += $(TRUSTM)/extras/pal/linux
INCDIR += $(TRUSTM)/extras/pal/linux/include
INCDIR += trustm_helper/include
INCDIR += trustm_provider
INCDIR += $(MBEDTLS_DIR)/include
#INCDIR += $(TRUSTM)/external/mbedtls/include/mbedtls
INCDIR += $(TRUSTM)/config
ifneq (,$(filter $(MBEDTLS_VARIANT),3 4))
INCDIR += $(MBEDTLS_INSTALL_DIR)/include
endif

ifdef INCDIR
INCSRC := $(shell find $(INCDIR) -name '*.h')
INCDIR := $(addprefix -I ,$(INCDIR))
endif

ifdef LIBDIR
	ifdef PALDIR
	        LIBSRC =  $(PALDIR)/pal.c	       
	        ifeq ($(BUILD_FOR_ULTRA96), YES)
	                 LIBSRC += $(PALDIR)/pal_gpio.c
        	endif
	        ifeq ($(USE_LIBGPIOD_RPI), YES)
	                 LIBSRC += $(PALDIR)/pal_gpio_gpiod.c
        	endif
	        LIBSRC += $(PALDIR)/pal_i2c.c
			LIBSRC += $(PALDIR)/pal_logger.c
			LIBSRC += $(PALDIR)/pal_os_datastore.c
	        LIBSRC += $(PALDIR)/pal_os_event.c
        	LIBSRC += $(PALDIR)/pal_os_lock.c
	        LIBSRC += $(PALDIR)/pal_os_timer.c
	        LIBSRC += $(PALDIR)/pal_os_memory.c
			ifeq ($(MBEDTLS_VARIANT),2)
			LIBSRC += $(TRUSTM)/extras/pal/pal_crypt_mbedtls.c
			else ifneq (,$(filter $(MBEDTLS_VARIANT),3 4))
			LIBSRC += $(TRUSTM)/extras/pal/pal_crypt_psa.c
			else
			LIBSRC += $(TRUSTM)/extras/pal/pal_crypt_openssl.c
			endif
			LIBSRC += $(TRUSTM)/extras/pal/linux/pal_shared_mutex.c       	
        	ifeq ($(USE_LIBGPIOD_RPI), YES)
	                LIBSRC += $(PALDIR)/target/gpiod/pal_ifx_i2c_config.c
        	endif
	        ifeq ($(BUILD_FOR_ULTRA96), YES)
                	LIBSRC += $(PALDIR)/target/ultra96/pal_ifx_i2c_config.c
        	endif
	endif

	LIBSRC += $(shell find $(LIBDIR) -name '*.c') 
	LIBOBJ := $(patsubst %.c,%.o,$(LIBSRC))
	LIB = libtrustm.so
endif

ifdef OTHDIR
	OTHSRC := $(shell find $(OTHDIR) -name '*.c')
	OTHOBJ := $(patsubst %.c,%.o,$(OTHSRC))
endif

ifdef APPDIR
	APPSRC := $(shell find $(APPDIR) -name '*.c')
	APPOBJ := $(patsubst %.c,%.o,$(APPSRC))
	APPS := $(patsubst %.c,%,$(APPSRC))
endif

ifdef PROVDIR
	PROVSRC := $(shell find $(PROVDIR) -name '*.c')
	PROVOBJ := $(patsubst %.c,%.o,$(PROVSRC))
	PROVIDER = trustm_provider.so
endif

CC = gcc
DEBUG = -g

LIBGPIOD_VERSION := $(shell pkg-config --modversion libgpiod 2>/dev/null)
ifeq ($(shell echo $(LIBGPIOD_VERSION) | cut -c1),1)
  CFLAGS += -DLIBGPIOD_V1
endif

CFLAGS += -c
ifeq ($(ARCH), arm64)
CFLAGS += -fPIC
endif
#CFLAGS += $(DEBUG)
CFLAGS += $(INCDIR)
CFLAGS += -Wall
CFLAGS += -Wno-format
ifeq ($(USE_LIBGPIOD_RPI), YES)
	  CFLAGS += -DHAS_LIBGPIOD
endif
#CFLAGS += -DENGINE_DYNAMIC_SUPPORT
CFLAGS += -DOPTIGA_COMMS_SET_RESET_SOFT
ifeq ($(MBEDTLS_VARIANT),2)
CFLAGS += -DMBEDTLS_USER_CONFIG_FILE=\"../../../$(MBEDTLS_CONFIG)\"
endif

LDFLAGS += -lpthread
LDFLAGS += -lssl
ifeq ($(USE_LIBGPIOD_RPI), YES)
  LDFLAGS += -lgpiod
endif  
LDFLAGS += -lcrypto
LDFLAGS += -lrt
LDFLAGS += -Wl,--no-undefined

LDFLAGS_1 = -L$(BINDIR) -Wl,-R$(BINDIR)
LDFLAGS_1 += -ltrustm

LDFLAGS_2 = -L/usr/local/ssl/lib
LDFLAGS_2 += -lssl
LDFLAGS_2 += -lcrypto

.Phony : install uninstall all clean

# Build mbedTLS 4.x and install headers/libs locally (needed for PSA headers)
ifneq (,$(filter $(MBEDTLS_VARIANT),3 4))
MBEDTLS_LIB := $(MBEDTLS_INSTALL_DIR)/lib/libmbedtls.a

$(MBEDTLS_LIB):
	@echo "******* Building+installing mbedTLS $(MBEDTLS_VARIANT) into $(MBEDTLS_INSTALL_DIR)"
	@cd $(MBEDTLS_DIR) && git submodule update --init --recursive
	@rm -rf $(MBEDTLS_BUILD_DIR) $(MBEDTLS_INSTALL_DIR)
	@mkdir -p $(MBEDTLS_BUILD_DIR)
	@cmake -S $(MBEDTLS_DIR) -B $(MBEDTLS_BUILD_DIR) -DCMAKE_INSTALL_PREFIX="$(abspath $(MBEDTLS_INSTALL_DIR))" -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_C_FLAGS="-DMBEDTLS_USER_CONFIG_FILE=\\\"$(abspath $(MBEDTLS_CONFIG))\\\""
	@cmake --build $(MBEDTLS_BUILD_DIR) -j2
	@cmake --install $(MBEDTLS_BUILD_DIR)
else
MBEDTLS_LIB :=
endif

ifneq (,$(filter $(MBEDTLS_VARIANT),3 4))
all : $(MBEDTLS_LIB) $(BINDIR)/$(LIB) $(APPS) $(BINDIR)/$(PROVIDER)
else
all : $(BINDIR)/$(LIB) $(APPS) $(BINDIR)/$(PROVIDER)
endif

install:
	@echo "Create symbolic link to the openssl provider $(PROVIDER_INSTALL_DIR)/$(PROVIDER)"
	@ln -s $(realpath $(BINDIR)/$(PROVIDER)) $(PROVIDER_INSTALL_DIR)/$(PROVIDER)
	@echo "Create symbolic link to trustm_lib $(LIB_INSTALL_DIR)/$(LIB)"
	@ln -s $(realpath $(BINDIR)/$(LIB)) $(LIB_INSTALL_DIR)/$(LIB)
	
uninstall: clean
	@echo "Removing openssl symbolic link from $(PROVIDER_INSTALL_DIR)"	
	@rm -rf $(PROVIDER_INSTALL_DIR)/$(PROVIDER)
	@echo "Removing trustm_lib $(LIB_INSTALL_DIR)/$(LIB)"
	@rm -rf $(LIB_INSTALL_DIR)/$(LIB)

clean :
	@echo "Removing *.o from $(LIBDIR)" 
	@rm -rf $(LIBOBJ)
	@echo "Removing *.o from $(OTHDIR)" 
	@rm -rf $(OTHOBJ)
	@echo "Removing *.o from $(APPDIR)"
	@rm -rf $(APPOBJ)
	@echo "Removing *.o from $(PROVDIR)"
	@rm -rf $(PROVOBJ)
	@echo "Removing all application from $(APPDIR)"	
	@rm -rf $(APPS)
	@echo "Removing all application from $(BINDIR)"	
	@rm -rf bin/*
	@echo "Removing all hidden files"	
	@rm -rf .trustm_*
			
$(BINDIR)/$(PROVIDER): %: $(PROVOBJ) $(INCSRC) $(BINDIR)/$(LIB)
	@echo "******* Linking $@ "
	@mkdir -p bin
	@$(CC)   $(PROVOBJ) $(LDFLAGS) $(LDFLAGS_1) $(LDFLAGS_2)  -shared -o $@
	
$(APPS): %: $(OTHOBJ) $(INCSRC) $(BINDIR)/$(LIB) %.o $(MBEDTLS_LIB)
			@echo "******* Linking $@ "
			@mkdir -p bin
			@$(CC) $@.o $(LDFLAGS_1) $(LDFLAGS) $(OTHOBJ) -o $@
			@mv $@ bin/.	

$(BINDIR)/$(LIB): %: $(LIBOBJ) $(INCSRC) $(MBEDTLS_LIB)
	@mkdir -p bin
	@$(CC) $(LIBOBJ) $(LDFLAGS)  -shared -o $@

$(LIBOBJ): %.o: %.c $(INCSRC) $(MBEDTLS_LIB)
	@echo "+++++++ Generating lib object: $< "
	@$(CC) $(CFLAGS) $< -o $@
	
$(APPOBJ): %.o: %.c $(INCSRC) $(MBEDTLS_LIB)
	@echo "+++++++ Generating app object: $< "
	@$(CC) $(CFLAGS) $< -o $@
    
$(PROVOBJ): %.o: %.c $(INCSRC) $(MBEDTLS_LIB)
	@echo "+++++++ Generating provider object: $< "
	@$(CC) $(CFLAGS) $< -o $@


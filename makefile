

# Check the adb command and store the device architecture in a variable if successful

.PHONY: all
.DEFAULT_GOAL := all

# check if env.mk exists, if this file exist, include it , or skip it 
ifneq ($(wildcard env.mk),)
    include env.mk
endif

ifeq ($(strip $(PLATFORM)),)

else
    include device_arch.mk
endif

ifeq ($(strip $(GAME_PACKAGE_NAME)),)
    TYPESCRIPT_FILE=index.ts
else
    TYPESCRIPT_FILE=games/index.$(GAME_PACKAGE_NAME).ts
endif

all: # check_arch build_c convert_so 
	./node_modules/.bin/frida-compile ${TYPESCRIPT_FILE} -o _agent.js 

convert_so:
	./node_modules/ts-frida/dist/bin/so2ts.py --no-content -b c/libs/$(DEVICE_ARCH)/libpatchgame.so -o modinfos/libmodpatchgame.ts

build_c:
	make -C c

tt:
	echo PLATFORM ${PLATFORM}
	echo GAME_PACKAGE_NAME ${GAME_PACKAGE_NAME}

clean:
	make -C c clean
	rm -fr modinfos/lib*.ts





LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE:= patchgame

LOCAL_SRC_FILES :=   \
    ../patchgame.cc \
    ../../node_modules/ts-frida/dist/nativeLib/imgui/imgui.cpp                    \
    ../../node_modules/ts-frida/dist/nativeLib/imgui/imgui_demo.cpp               \
    ../../node_modules/ts-frida/dist/nativeLib/imgui/imgui_draw.cpp               \
    ../../node_modules/ts-frida/dist/nativeLib/imgui/imgui_impl_android.cpp       \
    ../../node_modules/ts-frida/dist/nativeLib/imgui/imgui_impl_opengl3.cpp       \
    ../../node_modules/ts-frida/dist/nativeLib/imgui/imgui_tables.cpp             \
    ../../node_modules/ts-frida/dist/nativeLib/imgui/imgui_wrapper.cpp            \
    ../../node_modules/ts-frida/dist/nativeLib/imgui/imgui_widgets.cpp            \
    ../../node_modules/ts-frida/dist/nativeLib/utils.cc \
    ../../node_modules/ts-frida/dist/nativeLib/miniz.c

LOCAL_C_INCLUDES :=  \
    ../../node_modules/ts-frida/dist/nativeLib

LOCAL_LDLIBS := 
LOCAL_ARM_MODE := 
LOCAL_ALLOW_UNDEFINED_SYMBOLS := true
LOCAL_CFLAGS= -fno-exceptions -fno-stack-protector -z execstack
LOCAL_CPPFLAGS += -fvisibility=hidden 
include $(BUILD_SHARED_LIBRARY)



LOCAL_PATH := $(call my-dir)

# libpcap
include $(CLEAR_VARS)
LOCAL_MODULE := static_libpcap
LOCAL_SRC_FILES := ./libpcap/lib/libpcap.a
LOCAL_EXPORT_C_INCLUDES := ./libpcap/header
LOCAL_C_INCLUDES := ./libpcap/header
include $(PREBUILT_STATIC_LIBRARY)

# main module
include $(CLEAR_VARS)
LOCAL_MODULE := amca 
LOCAL_SRC_FILES := main.cpp packet.cpp memorymap.cpp module.cpp base64.cpp md5.cpp util.cpp
LOCAL_STATIC_LIBRARIES := static_libpcap
LOCAL_CFLAGS += -std=c++11
include $(BUILD_EXECUTABLE)

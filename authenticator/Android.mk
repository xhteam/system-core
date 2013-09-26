# Copyright (C) 2013 Quester Tech,Inc.
# Copyright (C) 2008 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


LOCAL_PATH:= $(call my-dir)

EMBEDDED_MINIUI:=true

include $(CLEAR_VARS)

LOCAL_CFLAGS := -DLOG_TAG=\"authenticator\" -DMULTI_LOCK_SUPPORT

LOCAL_SRC_FILES := \
	main.cpp \
	auth_core.cpp \
	auth_proto.cpp \
	auth_event.cpp \
	auth_algo.cpp \
	auth_utils.cpp


LOCAL_LDLIBS += -lpthread

LOCAL_MODULE := authenticator
LOCAL_MODULE_TAGS := optional



ifeq ($(EMBEDDED_MINIUI),)
LOCAL_C_INCLUDES := \
	$(call include-path-for, corecg graphics) \
	external/openssl/include
LOCAL_SHARED_LIBRARIES := \
	libcutils \
	libutils \
    libcrypto 
LOCAL_CFLAGS += -DLEGACY_UI
LOCAL_SRC_FILES += \
	auth_screen.cpp
LOCAL_SHARED_LIBRARIES+= \
	libbinder \
    libui \
	libskia \
    libsurfaceflinger_client	
else
LOCAL_SRC_FILES += \
	graphics.cpp \
	resources.cpp \
	auth_screen_miniui.cpp \
	md5.cpp

LOCAL_C_INCLUDES := \
	external/libpng \
	external/zlib
	
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT_SBIN)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_SBIN_UNSTRIPPED)

LOCAL_STATIC_LIBRARIES := \
	libminui libpixelflinger_static \
	libpng libz libstdc++ \
	libcutils libm libc	
endif


#
#
#TODO :build static executable 
#
#

include $(BUILD_EXECUTABLE)

define _add-authenticator-image
include $$(CLEAR_VARS)
LOCAL_MODULE := system_core_authenticator_$(notdir $(1))
LOCAL_MODULE_STEM := $(notdir $(1))
_img_modules += $$(LOCAL_MODULE)
LOCAL_SRC_FILES := $1
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $$(TARGET_ROOT_OUT)/res/images/authenticator
include $$(BUILD_PREBUILT)
endef

_img_modules :=
_images :=
$(foreach _img, $(call find-subdir-subdir-files, "images", "*.png"), \
  $(eval $(call _add-authenticator-image,$(_img))))

include $(CLEAR_VARS)
LOCAL_MODULE := authenticator_res_images
LOCAL_MODULE_TAGS := optional
LOCAL_REQUIRED_MODULES := $(_img_modules)
include $(BUILD_PHONY_PACKAGE)

_add-charger-image :=
_img_modules :=






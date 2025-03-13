TARGET := iphone:clang:latest:16.5
INSTALL_TARGET_PROCESSES = SpringBoard
ARCHS = arm64
DEBUG = 0
FINALPACKAGE = 1
FOR_RELEASE = 1
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Xcern

Xcern_FILES = Tweak.x fishhook.c
Xcern_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk

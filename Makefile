# Build linux-ptrace-init-inject.
#
#   make            # dynamic link
#   make static     # static link (portable single binary)
#   make clean

CXX ?= g++
CXXFLAGS ?= -O2 -std=c++17 -Wall
TARGET := inject

all: $(TARGET)

$(TARGET): main.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "built: $@"

static: main.cpp
	$(CXX) $(CXXFLAGS) -static -o $(TARGET) $<
	@echo "built: $@ (static)"

.PHONY: all static clean
clean:
	rm -f $(TARGET)

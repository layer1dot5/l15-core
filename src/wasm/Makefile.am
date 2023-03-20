# Emscripten build flags
AM_CXXFLAGS = -O2 -s WASM=1
AM_LDFLAGS = -O2 -s WASM=1

# If you want to use a specific Emscripten configuration file, uncomment and set EM_CONFIG_FILE
# to the path to your .emscripten file.
# AM_CXXFLAGS += --em-config $(EM_CONFIG_FILE)
# AM_LDFLAGS += --em-config $(EM_CONFIG_FILE)

# If you want to use a specific Emscripten SDK path, uncomment and set EM_SDK_PATH
# to the path to your Emscripten SDK folder.
# AM_CXXFLAGS += --em-sdk $(EM_SDK_PATH)
# AM_LDFLAGS += --em-sdk $(EM_SDK_PATH)

#my_project_CXXFLAGS = $(AM_CXXFLAGS)
#my_project_LDFLAGS = $(AM_LDFLAGS) -s EXPORTED_FUNCTIONS=['_main','getTimestamp'] --preload-file assets

L15_LIBS = \
 -lembind

bin_PROGRAMS = wasm-plugin
wasm_plugin_CXXFLAGS = $(AM_CXXFLAGS)
wasm_plugin_LDFLAGS = $(AM_LDFLAGS) -o wasm_plugin.html
#wasm_plugin_CXXFLAGS = -s WASM=1
#wasm_plugin_LDFLAGS = -s WASM=1
wasm_plugin_SOURCES = ord_plugin.cpp
wasm_plugin_LDADD = $(L15_LIBS)

clean-local:
	rm -f my_project.wasm my_project.wasm.map my_project.js

# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.13

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = "/Users/Quasar/Downloads/SEAL-master/basic encrypted controller"

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = "/Users/Quasar/Downloads/SEAL-master/basic encrypted controller"

# Include any dependencies generated for this target.
include CMakeFiles/encrypted_controller.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/encrypted_controller.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/encrypted_controller.dir/flags.make

CMakeFiles/encrypted_controller.dir/encrypted_controller_main.cpp.o: CMakeFiles/encrypted_controller.dir/flags.make
CMakeFiles/encrypted_controller.dir/encrypted_controller_main.cpp.o: encrypted_controller_main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/Users/Quasar/Downloads/SEAL-master/basic encrypted controller/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/encrypted_controller.dir/encrypted_controller_main.cpp.o"
	/usr/local/bin/g++-8  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/encrypted_controller.dir/encrypted_controller_main.cpp.o -c "/Users/Quasar/Downloads/SEAL-master/basic encrypted controller/encrypted_controller_main.cpp"

CMakeFiles/encrypted_controller.dir/encrypted_controller_main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/encrypted_controller.dir/encrypted_controller_main.cpp.i"
	/usr/local/bin/g++-8 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E "/Users/Quasar/Downloads/SEAL-master/basic encrypted controller/encrypted_controller_main.cpp" > CMakeFiles/encrypted_controller.dir/encrypted_controller_main.cpp.i

CMakeFiles/encrypted_controller.dir/encrypted_controller_main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/encrypted_controller.dir/encrypted_controller_main.cpp.s"
	/usr/local/bin/g++-8 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S "/Users/Quasar/Downloads/SEAL-master/basic encrypted controller/encrypted_controller_main.cpp" -o CMakeFiles/encrypted_controller.dir/encrypted_controller_main.cpp.s

# Object files for target encrypted_controller
encrypted_controller_OBJECTS = \
"CMakeFiles/encrypted_controller.dir/encrypted_controller_main.cpp.o"

# External object files for target encrypted_controller
encrypted_controller_EXTERNAL_OBJECTS =

encrypted_controller: CMakeFiles/encrypted_controller.dir/encrypted_controller_main.cpp.o
encrypted_controller: CMakeFiles/encrypted_controller.dir/build.make
encrypted_controller: /usr/local/lib/libseal.a
encrypted_controller: CMakeFiles/encrypted_controller.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir="/Users/Quasar/Downloads/SEAL-master/basic encrypted controller/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable encrypted_controller"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/encrypted_controller.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/encrypted_controller.dir/build: encrypted_controller

.PHONY : CMakeFiles/encrypted_controller.dir/build

CMakeFiles/encrypted_controller.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/encrypted_controller.dir/cmake_clean.cmake
.PHONY : CMakeFiles/encrypted_controller.dir/clean

CMakeFiles/encrypted_controller.dir/depend:
	cd "/Users/Quasar/Downloads/SEAL-master/basic encrypted controller" && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" "/Users/Quasar/Downloads/SEAL-master/basic encrypted controller" "/Users/Quasar/Downloads/SEAL-master/basic encrypted controller" "/Users/Quasar/Downloads/SEAL-master/basic encrypted controller" "/Users/Quasar/Downloads/SEAL-master/basic encrypted controller" "/Users/Quasar/Downloads/SEAL-master/basic encrypted controller/CMakeFiles/encrypted_controller.dir/DependInfo.cmake" --color=$(COLOR)
.PHONY : CMakeFiles/encrypted_controller.dir/depend


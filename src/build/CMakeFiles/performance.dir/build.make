# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

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
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/wujh/A2L_performance/performance/src

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/wujh/A2L_performance/performance/src/build

# Include any dependencies generated for this target.
include CMakeFiles/performance.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/performance.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/performance.dir/flags.make

CMakeFiles/performance.dir/performance.o: CMakeFiles/performance.dir/flags.make
CMakeFiles/performance.dir/performance.o: ../performance.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/wujh/A2L_performance/performance/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/performance.dir/performance.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/performance.dir/performance.o   -c /home/wujh/A2L_performance/performance/src/performance.c

CMakeFiles/performance.dir/performance.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/performance.dir/performance.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/wujh/A2L_performance/performance/src/performance.c > CMakeFiles/performance.dir/performance.i

CMakeFiles/performance.dir/performance.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/performance.dir/performance.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/wujh/A2L_performance/performance/src/performance.c -o CMakeFiles/performance.dir/performance.s

CMakeFiles/performance.dir/utils.o: CMakeFiles/performance.dir/flags.make
CMakeFiles/performance.dir/utils.o: ../utils.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/wujh/A2L_performance/performance/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/performance.dir/utils.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/performance.dir/utils.o   -c /home/wujh/A2L_performance/performance/src/utils.c

CMakeFiles/performance.dir/utils.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/performance.dir/utils.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/wujh/A2L_performance/performance/src/utils.c > CMakeFiles/performance.dir/utils.i

CMakeFiles/performance.dir/utils.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/performance.dir/utils.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/wujh/A2L_performance/performance/src/utils.c -o CMakeFiles/performance.dir/utils.s

# Object files for target performance
performance_OBJECTS = \
"CMakeFiles/performance.dir/performance.o" \
"CMakeFiles/performance.dir/utils.o"

# External object files for target performance
performance_EXTERNAL_OBJECTS =

performance: CMakeFiles/performance.dir/performance.o
performance: CMakeFiles/performance.dir/utils.o
performance: CMakeFiles/performance.dir/build.make
performance: /usr/local/lib/librelic.so
performance: /usr/local/lib/libpari.so
performance: CMakeFiles/performance.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/wujh/A2L_performance/performance/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable performance"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/performance.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/performance.dir/build: performance

.PHONY : CMakeFiles/performance.dir/build

CMakeFiles/performance.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/performance.dir/cmake_clean.cmake
.PHONY : CMakeFiles/performance.dir/clean

CMakeFiles/performance.dir/depend:
	cd /home/wujh/A2L_performance/performance/src/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/wujh/A2L_performance/performance/src /home/wujh/A2L_performance/performance/src /home/wujh/A2L_performance/performance/src/build /home/wujh/A2L_performance/performance/src/build /home/wujh/A2L_performance/performance/src/build/CMakeFiles/performance.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/performance.dir/depend


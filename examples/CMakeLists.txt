project(test)

include_directories(${CMAKE_SOURCE_DIR}/test/)
include_directories(${CMAKE_SOURCE_DIR}/APIhooklib/APIhooklib)

link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

add_executable( files files.cpp hooks.cpp hooks.h )
add_dependencies ( files APIhooklib )
target_link_libraries( files debug APIhooklib.lib )
target_link_libraries( files optimized APIhooklib.lib )

add_executable( network network.cpp hooks.cpp hooks.h )
add_dependencies ( network APIhooklib )
target_link_libraries( network debug APIhooklib.lib )
target_link_libraries( network optimized APIhooklib.lib )

add_executable( test test.cpp )
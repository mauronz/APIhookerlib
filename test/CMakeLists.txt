project(test)

include_directories(${CMAKE_SOURCE_DIR}/test/)
include_directories(${CMAKE_SOURCE_DIR}/APIhooklib/APIhooklib)

link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

set ( hdrs
	hooks.h
)

set ( srcs
	master.cpp
	hooks.cpp
	)

add_executable( master ${srcs} ${hdrs} )

add_dependencies ( master APIhooklib )

target_link_libraries(master debug APIhooklib.lib)
target_link_libraries(master optimized APIhooklib.lib)

add_executable(slave slave.cpp)
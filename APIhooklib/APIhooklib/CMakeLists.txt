project(APIhooklib)

include_directories(${CMAKE_SOURCE_DIR}/APIhooklib/APIhooklib)
include_directories(${CMAKE_SOURCE_DIR}/APIhooklib/libpeconv/include)
include_directories(${CMAKE_SOURCE_DIR}/APIhooklib/hook_engine)

link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

set ( hdrs
	APIhooklib.h
)

set ( srcs
	APIhooklib.cpp
	)

add_library ( ${PROJECT_NAME} SHARED ${hdrs} ${srcs} )

target_link_libraries(APIhooklib debug libpeconv.lib)
target_link_libraries(APIhooklib debug hook_engine.lib)

target_link_libraries(APIhooklib optimized libpeconv.lib)
target_link_libraries(APIhooklib optimized hook_engine.lib)
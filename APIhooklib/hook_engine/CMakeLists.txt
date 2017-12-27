project(hook_engine)

set (srcs
	hook_engine.cpp
	disassembler/hde32.c)

set (hdrs 
	hook_engine.h
	disassembler/hde32.h
	disassembler/table32.h)

add_library ( ${PROJECT_NAME} STATIC ${hdrs} ${srcs} )
# generator server makefile

add_compile_options(-std=c++11)

set(PROJ_NAME signing_server)
set(PROJ_INCLUDES "include")
set(PROJ_SOURCE "src/jsonhandle.cpp" "src/signinghandle.cpp" "src/peer.cpp" "main.cpp")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/")

# json libary
set (JSON_FOLDER "${CMAKE_SOURCE_DIR}/vendors/nlohmann_json")
message ("JSON FOLDER ${JSON_FOLDER}")

INCLUDE_DIRECTORIES("${PROJ_INCLUDES}" "${JSON_FOLDER}")
add_executable(${PROJ_NAME} ${PROJ_SOURCE})

#find required package
find_package(Threads REQUIRED)
find_package(ZeroMQ REQUIRED)
find_package(OpenSSL COMPONENTS SSL Crypto REQUIRED)


#link pthreads
if(THREADS_HAVE_PTHREAD_ARG)
  target_compile_options(${PROJ_NAME} PUBLIC "-pthread")
endif()
if(CMAKE_THREAD_LIBS_INIT)
  target_link_libraries(${PROJ_NAME} PUBLIC ${CMAKE_THREAD_LIBS_INIT})
endif()

## add the include directory to our compile directives
target_include_directories(${PROJ_NAME} PUBLIC ${Threads_INCLUDE_DIRS})
target_include_directories(${PROJ_NAME} PUBLIC ${ZeroMQ_INCLUDE_DIRS})

## at the 0mq library to our link directive
target_link_libraries(${PROJ_NAME} PUBLIC ${Threads_LIBRARIES})
target_link_libraries(${PROJ_NAME} PUBLIC ${ZeroMQ_LIBRARIES})

# use openssl
set (OPENSSL_USE_STATIC_LIBS TRUE)
target_include_directories(${PROJ_NAME} PUBLIC ${OpenSSL_INCLUDE_DIR})
target_link_libraries(${PROJ_NAME} PUBLIC ${OpenSSL_LIBRARIES})


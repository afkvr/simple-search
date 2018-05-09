# generator server makefile

add_compile_options(-std=c++11)

set(PROJ_NAME generator_server)
set(PROJ_INCLUDES "include" "${CMAKE_SOURCE_DIR}")
set(PROJ_SOURCE "src/jsonhandle.cpp" "src/numberhandle.cpp" "src/peer.cpp" "main.cpp" "${CMAKE_SOURCE_DIR}/utils/utils.cpp" "${CMAKE_SOURCE_DIR}/database/db_interface.cpp" "${CMAKE_SOURCE_DIR}/message/message.cpp")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/")

# json libary
set (JSON_FOLDER "${CMAKE_SOURCE_DIR}/vendors/nlohmann_json")
message ("JSON FOLDER ${JSON_FOLDER}")

#add elastic cpp to our project
set(ELASTIC_CPP_FOLDER "${CMAKE_SOURCE_DIR}/vendors/cpp-elasticsearch/src")
set(ELASTIC_CPP_SOURCE "${ELASTIC_CPP_FOLDER}/elasticsearch/elasticsearch.cpp" "${ELASTIC_CPP_FOLDER}/json/json.cpp" "${ELASTIC_CPP_FOLDER}/http/http.cpp")

set(ELASTIC_CPP_INC "${CMAKE_SOURCE_DIR}/vendors/cpp-elasticsearch/src")

message ("ELASTIC_CPP_INC content " ${ELASTIC_CPP_INC})
list(APPEND PROJ_SOURCE ${ELASTIC_CPP_SOURCE})

INCLUDE_DIRECTORIES("${PROJ_INCLUDES}" "${ELASTIC_CPP_INC}" "${JSON_FOLDER}")
add_executable(${PROJ_NAME} ${PROJ_SOURCE})

#find required package
find_package(Threads REQUIRED)
find_package(ZeroMQ REQUIRED)
find_package (sodium REQUIRED)
find_package(Boost COMPONENTS system filesystem REQUIRED)
find_package(OpenSSL COMPONENTS SSL Crypto REQUIRED)

#link pthreads
if(THREADS_HAVE_PTHREAD_ARG)
  target_compile_options(${PROJ_NAME} PUBLIC "-pthread")
endif()
if(CMAKE_THREAD_LIBS_INIT)
  target_link_libraries(${PROJ_NAME} PUBLIC ${CMAKE_THREAD_LIBS_INIT})
endif()

#sodium library
#use static lib
set(sodium_USE_STATIC_LIBS TRUE)

target_include_directories(${PROJ_NAME} PUBLIC ${sodium_INCLUDE_DIR})
target_link_libraries(${PROJ_NAME} PUBLIC ${sodium_LIBRARY_RELEASE})

#use boost lib
set(Boost_USE_STATIC_LIBS        ON)  # only find static libs
target_link_libraries (${PROJ_NAME} PUBLIC ${Boost_FILESYSTEM_LIBRARY} ${Boost_SYSTEM_LIBRARY})

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


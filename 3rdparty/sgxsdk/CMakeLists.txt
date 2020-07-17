# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (OE_SGX)
  target_include_directories(oehost PRIVATE ${PROJECT_SOURCE_DIR}/3rdparty/sgxsdk/include)
endif ()

cmake_minimum_required(VERSION 3.14)
project(KeystoreSignerPlugin LANGUAGES CXX)

if(DEFINED ENV{LOGOS_MODULE_BUILDER_ROOT})
    include($ENV{LOGOS_MODULE_BUILDER_ROOT}/cmake/LogosModule.cmake)
else()
    message(FATAL_ERROR "LOGOS_MODULE_BUILDER_ROOT is not set.")
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/metadata.json
               ${CMAKE_CURRENT_BINARY_DIR}/metadata.json COPYONLY)

# Rust cdylib module: the `codegen.rust` block in metadata.json makes the
# builder generate rust-lib/generated/provider_gen.rs from keystore_signer.lidl
# and compile the crate to a static archive, which LogosModule.cmake links
# into the plugin shell. No SOURCES — there is no hand-written C++.
logos_module(NAME keystore_signer)

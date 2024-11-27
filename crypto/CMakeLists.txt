# crypto

# Option to select the crypto library
option(USE_MBEDTLS "Use MbedTLS instead of OpenSSL" ON)

if(USE_MBEDTLS)
	add_lib_batch(vmecs-crypto STATIC "*.c")
	target_link_libraries(vmecs-crypto mbedtls mbedcrypto)
	target_compile_definitions(vmecs-crypto PUBLIC USE_MBEDTLS)
else()
	add_lib_batch(vmecs-crypto STATIC "*.c")
	target_link_libraries(vmecs-crypto ssl crypto)
endif()



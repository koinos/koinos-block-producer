hunter_config(Boost
   VERSION ${HUNTER_Boost_VERSION}
   CMAKE_ARGS
      USE_CONFIG_FROM_BOOST=ON
      Boost_USE_STATIC_LIBS=ON
      Boost_NO_BOOST_CMAKE=ON
)

hunter_config(rabbitmq-c
   URL "https://github.com/alanxz/rabbitmq-c/archive/b8e5f43b082c5399bf1ee723c3fd3c19cecd843e.tar.gz"
   SHA1 "35d4ce3e4f0a5348de64bbed25c6e1df72da2594"
   CMAKE_ARGS
      ENABLE_SSL_SUPPORT=OFF
)

hunter_config(libsecp256k1
   URL "https://github.com/soramitsu/soramitsu-libsecp256k1/archive/c7630e1bac638c0f16ee66d4dce7b5c49eecbaa5.tar.gz"
   SHA1 "0534fa8948f279b26fd102905215a56f0ad7fa18"
)

hunter_config(koinos_log
   GIT_SUBMODULE "libraries/log"
   CMAKE_ARGS
      BUILD_TESTS=OFF
)

hunter_config(koinos_util
   GIT_SUBMODULE "libraries/util"
   CMAKE_ARGS
      BUILD_TESTS=OFF
)

hunter_config(koinos_types
   GIT_SUBMODULE "libraries/types"
   CMAKE_ARGS
      BUILD_TESTS=OFF
)

hunter_config(koinos_exception
   GIT_SUBMODULE "libraries/exception"
   CMAKE_ARGS
      BUILD_TESTS=OFF
)

hunter_config(koinos_crypto
   GIT_SUBMODULE "libraries/crypto"
   CMAKE_ARGS
      BUILD_TESTS=OFF
)

hunter_config(koinos_mq
   GIT_SUBMODULE "libraries/mq"
   CMAKE_ARGS
      BUILD_TESTS=OFF
)

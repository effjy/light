gcc -O2 -Wall -Wextra -Ikyber/ref -o light light.c \
    kyber/ref/libpqcrystals_kyber1024_ref.a \
    -lssl -lcrypto -lsodium -largon2

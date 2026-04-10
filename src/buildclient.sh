swiftc -emit-library -static -o libswift_crypto.a crypto_bridge.swift
cc wg_client3.c \
   -L. -lswift_crypto \
   -L../build -lwg \
   -lpthread \
   -framework Foundation \
   -framework CryptoKit \
   -L /usr/lib/swift \
   -o wg_client_final

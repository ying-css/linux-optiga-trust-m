#!/bin/sh
sudo apt update
sudo apt -y install git gcc build-essential libssl-dev gpiod libgpiod-dev curl xxd cmake

# Configuration, choose the version of mbedTLS
MBEDTLS_VARIANT=4
set -e
echo "-----> Build Trust M Linux Tools and provider"
if [ "$MBEDTLS_VARIANT" -eq 4 ]; then
(
    echo "-----> Generate mbedtls config files" 
    cd trustm_lib/external/mbedtls-4.x 
    python3 framework/scripts/make_generated_files.py
)
(
    echo "-----> Generate PSA config files"
    cd trustm_lib/external/mbedtls-4.x/tf-psa-crypto \ 
    python3 framework/scripts/make_generated_files.py
)
fi
sudo make uninstall MBEDTLS_VARIANT="$MBEDTLS_VARIANT"
make clean MBEDTLS_VARIANT="$MBEDTLS_VARIANT"
make -j5 MBEDTLS_VARIANT="$MBEDTLS_VARIANT"
sudo make install MBEDTLS_VARIANT="$MBEDTLS_VARIANT"
echo "-----> Build Protected Update Set tool"
cd ex_protected_update_data_set/Linux/
make clean
make -j5
sudo make install

#!/bin/bash
source config.sh

rm *.sig

echo "Generate new ECC256 keypair"
#~ openssl pkey -provider trustm_provider -provider default -propquery provider=trustm -in 0xe0f1:*:NEW:0x03:0x13 -out key.pem
openssl ecparam --provider trustm_provider --provider default -name prime256v1:0xe0f3 -genkey -out ecckey.pem
#~ openssl ecparam --provider trustm_provider --provider default -name prime256v1:0xe0f1:*:0x13 -genkey -out ecckey.pem
#~ echo "Display the customized key file"
openssl ec -in ecckey.pem -text


#~ openssl ecparam -provider trustm_provider -provider default -propquery provider=trustm -name prime256v1:0xe0f1:*:0x13 -genkey -out ecckey_ref.pem
#~ openssl genpkey -provider trustm_provider -algorithm EC -pkeyopt group:P-256 -pkeyopt key_ref:0xe0f1:*:0x13 -out ecckey_ref.pem

#~ echo "Display the customized key file"
#~ openssl ec -in key.pem -text

#~ echo "Extract out the public key"
#~ openssl ec -in key.pem -pubout -conv_form uncompressed -out e0f1_pub.pem

#~ echo -n "abcde12345abcde12345abcde12345ab" > testdata.txt
#~ echo "-----> Sign the data"
#~ openssl pkeyutl -provider trustm_provider -provider default -sign -rawin -inkey key.pem -in testdata.txt -out testdata.sig

#~ echo "-----> Verify the Signature"
#~ openssl pkeyutl -verify -pubin -inkey e0f1_pub.pem -rawin -in testdata.txt -sigfile testdata.sig


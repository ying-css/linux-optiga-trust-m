#!/bin/bash
source config.sh

echo "Server1: -----> Generate Server ECC Private Key"
openssl ecparam -out server1_privkey.pem -name prime256v1 -genkey
echo "Server1:-----> Generate Server ECC Keys CSR"
openssl req -new  -key server1_privkey.pem -subj "/C=SG/CN=Server1/O=Infineon" -out server1.csr
echo "Server1:-----> Generate Server cetificate by using CA"
openssl x509 -req -in server1.csr -CA $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem -CAkey $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem -CAcreateserial -out server1.crt -days 365 -sha256 -extfile ../openssl.cnf -extensions cert_ext
openssl x509 -in server1.crt -text -purpose

echo "Display csr.pem"
openssl req -in csr.pem -pubkey -noout
openssl req -in csr.pem -text -noout

echo "Client1:-----> Creates customized key file"
openssl pkey -provider trustm_provider -provider default -propquery provider=trustm -in 0xe0f1:^ -out key.pem
openssl ec -in key.pem -text

echo "Client1:-----> Extract Public Key from CSR"
openssl req -in csr.pem -pubkey -noout -out client1_e0f1.pub
openssl pkey -in client1_e0f1.pub -pubin -text

echo "Client1:-----> Generate Client cetificate by using CA"
openssl x509 -req -in csr.pem -CA $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA.pem -CAkey $CERT_PATH/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem -CAcreateserial -out ccode_gen.crt -days 365 -sha256



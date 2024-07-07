#!/bin/bash

# https://w3challs.com/challenges/crypto/shadow

function downloadAndExtractDictionary() {
    wget https://raw.githubusercontent.com/zacheller/rockyou/master/rockyou.txt.tar.gz
    tar -xf rockyou.txt.tar.gz

    # wget https://raw.githubusercontent.com/josuamarcelc/common-password-list/main/rockyou.txt/rockyou.txt.zip
    # unzip rockyou.txt.zip
}

function decryptHash() {
    hashcat -m 500 -a 0 shadow rockyou.txt
}

downloadAndExtractDictionary
decryptHash

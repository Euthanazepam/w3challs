#!/bin/bash

# https://w3challs.com/challenges/crypto/shadow

DICTIONARY=rockyou.txt
FILE=shadow
POTFILE=~/.local/share/hashcat/hashcat.potfile

function removePotFile() {
  if [ -f $POTFILE ]; then
    rm $POTFILE
  fi
}

function downloadAndExtractDictionary() {
  if [ ! -f $DICTIONARY ]; then
    wget https://raw.githubusercontent.com/zacheller/rockyou/master/rockyou.txt.tar.gz
    tar -xf rockyou.txt.tar.gz
#    wget https://raw.githubusercontent.com/josuamarcelc/common-password-list/main/rockyou.txt/rockyou.txt.zip
#    unzip rockyou.txt.zip
  fi
}

function decryptHash() {
  hashcat -m 500 -a 0 $FILE $DICTIONARY
  cat $POTFILE | cut -d : -f 2
}

removePotFile
downloadAndExtractDictionary
decryptHash

#!/bin/bash

# This script cracks the password by the hash from the task https://w3challs.com/challenges/crypto/shadow

DICTIONARY=rockyou.txt
FILE=shadow
POTFILE=~/.local/share/hashcat/hashcat.potfile
PACKAGE_NAME="hashcat"

function checkHashcat()
  # Check if hashcat is installed.
  if [[ ! $(pacman -Ss $PACKAGE_NAME) ]]; then
    echo -e "$PACKAGE_NAME isn't installed\nInstall it with 'pacman -Sy $PACKAGE_NAME'"
    exit 1
  fi

function removePotFile() {
  # Clears potfile with previously cracked passwords.
  if [ -f $POTFILE ]; then
    rm $POTFILE
  fi
}

function downloadAndExtractDictionary() {
  # Downloads the archive with the rockyou.txt dictionary and unpacks it. 
  if [ ! -f $DICTIONARY ]; then
    wget https://raw.githubusercontent.com/zacheller/rockyou/master/rockyou.txt.tar.gz
    tar -xf rockyou.txt.tar.gz
#    wget https://raw.githubusercontent.com/josuamarcelc/common-password-list/main/rockyou.txt/rockyou.txt.zip
#    unzip rockyou.txt.zip
  fi
}

function decryptHash() {
  # Cracks password by dictionary for hash from shadow file.
  hashcat -m 500 -a 0 $FILE $DICTIONARY
  cat $POTFILE | cut -d : -f 2
}

checkHashcat
removePotFile
downloadAndExtractDictionary
decryptHash

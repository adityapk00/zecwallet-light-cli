#!/bin/bash
# This script depends on a docker image already being built
# To build it, 
# cd docker
# docker build --tag rustbuild:latest .

POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -v|--version)
    APP_VERSION="$2"
    shift # past argument
    shift # past value
    ;;
    *)    # unknown option
    POSITIONAL+=("$1") # save it in an array for later
    shift # past argument
    ;;
esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

if [ -z $APP_VERSION ]; then echo "APP_VERSION is not set"; exit 1; fi

# Write the version file
echo "pub const VERSION:&str = \"$APP_VERSION\";" > cli/src/version.rs

# First, do the tests
cd lib && cargo test --release
retVal=$?
if [ $retVal -ne 0 ]; then
    echo "Error"
    exit $retVal
fi
cd ..

# Compile for mac directly
cargo build --release 

#macOS
rm -rf target/macOS-zecwallet-cli-v$APP_VERSION
mkdir -p target/macOS-zecwallet-cli-v$APP_VERSION
cp target/release/zecwallet-cli target/macOS-zecwallet-cli-v$APP_VERSION/

# Now sign and zip the binaries
# macOS
gpg --batch --output target/macOS-zecwallet-cli-v$APP_VERSION/zecwallet-cli.sig --detach-sig target/macOS-zecwallet-cli-v$APP_VERSION/zecwallet-cli 
cd target
cd macOS-zecwallet-cli-v$APP_VERSION
gsha256sum zecwallet-cli > sha256sum.txt
cd ..
zip -r macOS-zecwallet-cli-v$APP_VERSION.zip macOS-zecwallet-cli-v$APP_VERSION 
cd ..

# For Windows and Linux, build via docker
docker run --rm -v $(pwd)/:/opt/zecwallet-light-cli rustbuild:latest bash -c "cd /opt/zecwallet-light-cli && cargo build --release && cargo build --release --target armv7-unknown-linux-gnueabihf && cargo build --release --target aarch64-unknown-linux-gnu && SODIUM_LIB_DIR='/opt/libsodium-win64/lib/' cargo build --release --target x86_64-pc-windows-gnu"

#Linux
rm -rf target/linux-zecwallet-cli-v$APP_VERSION
mkdir -p target/linux-zecwallet-cli-v$APP_VERSION
cp target/release/zecwallet-cli target/linux-zecwallet-cli-v$APP_VERSION/
gpg --batch --output target/linux-zecwallet-cli-v$APP_VERSION/zecwallet-cli.sig --detach-sig target/linux-zecwallet-cli-v$APP_VERSION/zecwallet-cli
cd target
cd linux-zecwallet-cli-v$APP_VERSION
gsha256sum zecwallet-cli > sha256sum.txt
cd ..
zip -r linux-zecwallet-cli-v$APP_VERSION.zip linux-zecwallet-cli-v$APP_VERSION 
cd ..


#Windows
rm -rf target/Windows-zecwallet-cli-v$APP_VERSION
mkdir -p target/Windows-zecwallet-cli-v$APP_VERSION
cp target/x86_64-pc-windows-gnu/release/zecwallet-cli.exe target/Windows-zecwallet-cli-v$APP_VERSION/
gpg --batch --output target/Windows-zecwallet-cli-v$APP_VERSION/zecwallet-cli.sig --detach-sig target/Windows-zecwallet-cli-v$APP_VERSION/zecwallet-cli.exe
cd target
cd Windows-zecwallet-cli-v$APP_VERSION
gsha256sum zecwallet-cli.exe > sha256sum.txt
cd ..
zip -r Windows-zecwallet-cli-v$APP_VERSION.zip Windows-zecwallet-cli-v$APP_VERSION 
cd ..


#Armv7
rm -rf target/Armv7-zecwallet-cli-v$APP_VERSION
mkdir -p target/Armv7-zecwallet-cli-v$APP_VERSION
cp target/armv7-unknown-linux-gnueabihf/release/zecwallet-cli target/Armv7-zecwallet-cli-v$APP_VERSION/
gpg --batch --output target/Armv7-zecwallet-cli-v$APP_VERSION/zecwallet-cli.sig --detach-sig target/Armv7-zecwallet-cli-v$APP_VERSION/zecwallet-cli
cd target
cd Armv7-zecwallet-cli-v$APP_VERSION
gsha256sum zecwallet-cli > sha256sum.txt
cd ..
zip -r Armv7-zecwallet-cli-v$APP_VERSION.zip Armv7-zecwallet-cli-v$APP_VERSION 
cd ..


#AARCH64
rm -rf target/aarch64-zecwallet-cli-v$APP_VERSION
mkdir -p target/aarch64-zecwallet-cli-v$APP_VERSION
cp target/aarch64-unknown-linux-gnu/release/zecwallet-cli target/aarch64-zecwallet-cli-v$APP_VERSION/
gpg --batch --output target/aarch64-zecwallet-cli-v$APP_VERSION/zecwallet-cli.sig --detach-sig target/aarch64-zecwallet-cli-v$APP_VERSION/zecwallet-cli
cd target
cd aarch64-zecwallet-cli-v$APP_VERSION
gsha256sum zecwallet-cli > sha256sum.txt
cd ..
zip -r aarch64-zecwallet-cli-v$APP_VERSION.zip aarch64-zecwallet-cli-v$APP_VERSION 
cd ..

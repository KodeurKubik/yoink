#!/bin/bash
# should be run on mac and from main folder :)
# uh the yoink-demo folder should already exist and have a ./test folder in it for the demo

rm -f yoink-demo.zip


# Add the random files lol
cp ./server/.yoinkignore-demo ./yoink-demo/.yoinkignore
cp ./server/.yoinkpass-demo ./yoink-demo/.yoinkpass


# Build server
cd server

mv .yoinkignore .yoinkignore-save
cp .yoinkignore-demo .yoinkignore

mv .yoinkpass .yoinkpass-save
cp .yoinkpass-demo .yoinkpass

mv src/.yoinkconfig src/.yoinkconfig-save
cp src/.yoinkconfig-demo src/.yoinkconfig


cargo build --release
cp ./target/release/yoink-server ../yoink-demo/yoink-server-mac
upx --best --lzma ../yoink-demo/yoink-server-mac
cargo build --release --target x86_64-pc-windows-gnu
cp ./target/x86_64-pc-windows-gnu/release/yoink-server.exe ../yoink-demo/yoink-server-win.exe
upx --best --lzma ../yoink-demo/yoink-server-win.exe


rm .yoinkignore
mv .yoinkignore-save .yoinkignore

rm .yoinkpass
mv .yoinkpass-save .yoinkpass

rm src/.yoinkconfig
mv src/.yoinkconfig-save src/.yoinkconfig


# Build client
cd ../client

mv src/.yoinkconfig src/.yoinkconfig-save
cp src/.yoinkconfig-demo src/.yoinkconfig


cargo build --release
cp ./target/release/yoink-client ../yoink-demo/yoink-client-mac
upx --best --lzma ../yoink-demo/yoink-client-mac
cargo build --release --target x86_64-pc-windows-gnu
cp ./target/x86_64-pc-windows-gnu/release/yoink-client.exe ../yoink-demo/yoink-client-win.exe
upx --best --lzma ../yoink-demo/yoink-client-win.exe


rm src/.yoinkconfig
mv src/.yoinkconfig-save src/.yoinkconfig


# Zip it
cd ..
zip -r yoink-demo.zip yoink-demo
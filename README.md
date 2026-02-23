# Yoink

Synchronize a folder over to a distant server. It’s basically a git but overkilled and made in rust 🦀

## Features ✨

- Per-user storage and password
- Only updates what changed (using blake3 hashes)
- SMALL binaries (and FAST) (thanks rust 🦀)
- Custom RSA encryption (if unsecured / http)

## Demo:

https://github.com/user-attachments/assets/856f4d77-71b0-4e0f-b186-614a9dd84a64

## Use yourself

You should first rename and fill all files called `.something-demo` with 'something' being 'yoinkconfig', 'yoinkpass', etc.

Then you can build and run the server with

```sh
cd server && cargo run
```

And the client with

```sh
cd client && cargo run
```

For release builds, you should first `build --release` and then move the executable to somewhere. The `data` folder of the server will end up in the same folder as the executable.

### License

(c) 2026 Kodeur_Kubik - Code available under the MIT License

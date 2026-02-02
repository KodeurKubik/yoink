# Yoink

Synchronize a folder over to a distant server. It’s basically a git but overkilled and made in rust 🦀

## Features ✨

- Per-user storage and password
- Only updates what changed (using blake3 hashes)
- SMALL binaries (and FAST) (thanks rust 🦀)

## Demo:

(will upload soon)

## Use yourself

You should first rename and fill all files called `.something-demo` with 'something' being 'yoinkconfig', 'yoinkpass', etc.

Then you can build and run the server with

```sh
cd server && cargo run --release
```

And the client with

```sh
cd client && cargo run --release
```

### License

(c) 2026 Kodeur_Kubik - Code available under the MIT License

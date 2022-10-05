This is a simple test program to retrieve files over TLS 1.2/1.3 and HTTP/1.0. It embeds only the ISRG Root X1 certificate, so it should be able to download any Let's Encrypt-secured page.

It's based on the WolfSSL [example file implementing a TLS client with I/O callbacks](https://github.com/wolfSSL/wolfssl-examples/blob/master/tls/client-tls-callback.c).

I find that it works fine when WolfSSL is compiled **without** the `--disable-asm` switch (on my Intel MacBook Pro 13" 2020, Monterey 12.6, Apple clang version 14.0.0 (clang-1400.0.29.102)).

But when it's compiled **with** `--disable-asm`, either on my Mac or with emscripten, I get -188 errors (ASN sig error, no CA signer to verify certificate) on the same sites.


## Steps to reproduce

On a Mac with homebrew, [download WolfSSL from GitHub releases](https://github.com/wolfSSL/wolfssl/releases/tag/v5.5.1-stable), untar, and compile without `--disable-asm`:

```
brew install autoconf automake libtool

cd wolfssl-5.5.1-stable

./autogen.sh

./configure \
  --disable-filesystem --disable-examples --disable-oldtls \
  --enable-sni --enable-tls13 \
  --enable-altcertchains

make
make install
```

Brief notes on these configure options:

* `--enable-altcertchains` appears to be [required to accept Let's Encrypt certs](https://github.com/wolfSSL/wolfssl/issues/4443)
* `--disable-filesystem` and `--disable-asm` owe to the fact we're going to be compiling with emscripten later
* We need SNI


Next, download, compile and run this program like so:

```
cd wolfssl-disable-asm-trouble
make tls-test

./tls-test vercel.com 443 /
```

You should find that this makes a successful https request and emits interleaved binary data and the content of the HTML page.

Now, recompile WolfSSL with `--disable-asm`.

```
cd wolfssl-5.5.1-stable

make clean

./autogen.sh

./configure \
  --disable-filesystem --disable-examples --disable-oldtls \
  --enable-sni --enable-tls13 \
  --enable-altcertchains --disable-asm

make
make install
```

When you now re-run `tls-test`, you may see this message at the end of the (much shorter) output: `ERROR: failed to connect to wolfSSL, error -188`.


# Obsidian
An abstraction layer that sits on top of OpenSSL, providing a more modern way to interact with it using C++, in the form of an independent static library that can be linked in place of OpenSSL's static libraries.

The desire for this came when I found myself re-implementing the same abstractions across various C++ projects that rely on OpenSSL for cryptography, and decided it would be better to turn those abstractions into their own independent repository.

Why abstract it at all? Well, OpenSSL is fundamentally a C library that was never designed with the more modern features we now have in C++ in mind, which makes using OpenSSL in its natural form feel quite jarring within the context of a modern C++ codebase. This is my solution.

In addition to providing abstractions for OpenSSL, I also wanted to include certain quality of life features that I often find myself re-using within projects where cryptography is involved, e.g. base16/hex encoding, pkcs7 padding, etc...

## Goals & Contribution
As of right now, this exists mainly to make my life easier, and as such, my priority isn't to abstract the entire OpenSSL library, as that would be quite a massive endeavor. Instead, I am focusing on the parts of OpenSSL that I use the most. However if you would like to contribute and expand upon the existing abstractions by providing your own abstractions of a part of OpenSSL that isn't covered, feel free to submit a pull request.

## Building
It goes without saying, but to build this library, you must have OpenSSL already installed on your system. Scripts will automate this process in the future, but as of right now, simply modify the `CMakeLists.txt` file to point to the relevant OpenSSL `lib/` and `include/` directories on your system. If you intend on building the tests as well, which rely on Google's gtest library, then make sure to point `CMakeLists.txt` to the `lib/` and `include/` for gtest as well. This entire process will be automated eventually.

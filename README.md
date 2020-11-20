# Citadel

Citadel is a high level API around [NIOSSH](https://github.com/apple/swift-nio-ssh). It aims to add what's out of scope for NIOSSH, lending code from my private tools.

It features the following helpers:

- [x] TCP-IP forwarding child channels
- [x] Basic SFTP Client

## TODO

A couple of code is held back until further work in SwiftNIO SSH is completed.

- [ ] RSA Authentication (implemented, but in a [fork of NIOSSH](https://github.com/Joannis/swift-nio-ssh-1/pull/1))
- [ ] SSH Key format parsing (just haven't had the time to make a public API yet)

## Contributing

I'm happy to accept ideas and PRs for new API's.

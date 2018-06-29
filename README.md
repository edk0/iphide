# iphide

structure-preserving encryption for IP addresses

Home-grown crypto features ahead, so I'll include the standard warning about
feet and bazookas, though in this case I'd posit that very little could be worse
than current alternatives ;)

The encryption key is currently compiled into the binary.

I wrote this in the hope of solving all the problems with IP cloaking on IRC. My
attempt encrypts each bit of an IP address based on all the bits preceding it,
preserving the prefix structure of IP addresses:

```console
$ ./iphide 1.1.1.1
1.1.1.1 -> 8.33.150.83
$ ./iphide 1.1.200.200
1.1.200.200 -> 8.33.1.83
```

even—uniquely, as far as I'm aware—in the middle of octets:

```console
$ ./iphide 1.1.64.1
1.1.64.1 -> 8.33.234.173
$ ./iphide 1.1.96.1
1.1.96.1 -> 8.33.221.132
```

while revealing as little information as possible about their contents: You can
tell how many bits of prefix two encrypted IP addresses share, but nothing else.
In order to improve privacy at the expense of structure-preservingness, an
prefix of the IP address can use full-blown format-preserving encryption instead
(12 bits by default for V4 addresses, but it's configurable in the source).

Of course, since everything we're doing is encryption (and not hashing), this
process is guaranteed to be completely collision-free and reversible, given the
key:

```console
$ ./iphide ?8.33.221.132
8.33.221.132 -> 1.1.96.1
```

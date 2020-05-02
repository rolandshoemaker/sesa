# sesa - Secure Enclave powered SSH Agent

> **WARNING:** my lack of objective-c experience is only rivaled by my lack of macOS API experience, be warned, this code may not work the way you expect it to, or I intend it to.

Usage should be pretty straight forward:

```
./sesa -sock ~/sesa.sock &
export SSH_AUTH_SOCK=~/sesa.sock
ssh roland@somewhere
```

This is a one trick pony, if you still want to use your system SSH agent, i.e. because you want to use the keys in `~/.ssh`, you'll need to figure that out yourself. You'll probably want to do something like defining per-host agents using `IdentityAgent` in your SSH config.

Adding keys to the secure enclave is up to you. I have a WIP tool, `/tool/main.go`, which can do it, but it still needs work to actually be useful.

# sesa - Secure Enclave powered SSH Agent

> **WARNING:** my lack of objective-c experience is only rivaled by my lack of macOS API experience, be warned, this code may not work the way you expect it to, or I intend it to.

Usage should be pretty straight forward:

```
./sesa -sock ~/sesa.sock &
export SSH_AUTH_SOCK=~/sesa.sock
ssh roland@somewhere
```

Both `sesa` and `sesa-tool` need to be `codesign`d with entitlements in order to work, otherwise `amfid` and `taskgated-helper` will just kill them. They both require at least the `com.apple.application-identifier` and `keychain-access-groups` entitlements set. The signing cert and entitlements values will need to match an installed provisioning profile.

This is a one trick pony, if you still want to use your system SSH agent, i.e. because you want to use the keys in `~/.ssh`, you'll need to figure that out yourself. You'll probably want to do something like defining per-host agents using `IdentityAgent` in your SSH config.

## Managing SE keys

Apple doesn't provide an easy way to manipulate the contents of the enclave. I've written a small(ish) tool to add/list/delete keys for use with `sesa`, which is in `sesa-tool/`. Once built and signed, it can be used to generate keys and will output the SSH public key format expected for `authorized_keys` files.

```
$ sesa-tool generate -key-label se-ssh-key
```

# TIG

Tig is a git alternative to back up your codebase or data.

The design considerations were the following.

- Way more code is be generated with AI and people.
- Storage is cheaper, simple consistency is important.
- This makes ordering obsolete. Generative AI works on parallel versions.
- Time stamps are less important, coding is non-linear.
- Stable codebase is important.
- Revisions need to be tested and reviewed before use.
- The stable version is highly utilized version more likely than the latest one.
- We still need a way to securely iterate through all versions.
- Api key is good enough especially if it can only be set by the owner of the server.
- Api key can be extended with 2FA wrappers easily.

## The power

There are some ways developers can extend it to be powerful.

- Backup tools can directly work with uploaded data easily.
- The client can address the file any time with its SHA256 hash.
- The client can XOR split the stream to two different cloud providers making risks lower.
- The client can do striping to two or more different cloud providers doubling bandwidth.
- File cleanup delay can be adjusted to act like a cache or the legal backup.
- File hashes instead act like page and segment addresses of Intel and AMD process pages.
- Such a setup can work to make distributed processes with ease.
- Memory mapped, and swap volumes can speed up frequently accessed files.
- A wrapper can accept any uploads, but allow only internal downloads.

## Examples

TODO
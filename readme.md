# TIG

Tig is a git alternative to upload your codebase to.

The design considerations were the following.

- Code will be generated with AI and people.
- This makes ordering obsolete. Generative AI works in parallel.
- Time stamp is less important.
- Versions need to be tested and reviewed before use.
- The stable version is the good version more likely than the latest one.
- We need a way to securely iterate through all versions.
- Api key is good enough especially if it can only be set by the owner of the server.

## The power

There are some ways developers can extend it to be powerful.

- Backup tools can directly work on uploaded data easily.
- The client can address the file any time with its SHA256 hash.
- The client can split the stream into to XOR streams uploaded to two different cloud providers making risks and pricing lower.
- The client can do striping to two different cloud providers doubling bandwidth.
- Cleanup time can be adjusted file hashes acting like page and segment addresses.
- Such a setup can work with memory mapped volumes to make distributed processes with ease.

## Examples

TODO
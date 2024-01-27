# TIG

Tig is a git alternative to back up your codebase or data.

The design considerations were the following.

- AI generates more code than people.
- Storage is cheaper, simple consistency is more important than disk usage.
- Change ordering is obsolete. Generative AI works on parallel versions.
- Time stamps are less important, coding is non-linear.
- Stable codebase is important. Hash identifies an entire repo, not a diff.
- Revisions need to be tested and reviewed before use. Who wrote it is obsolete.
- The stable version is a highly utilized version more likely than the latest one.
- Storing more revisions is more important than full push updates of repo history.
- We still need a way to securely iterate through all versions.
- Api key is good enough especially if it can only be set by the owner of the server.
- Api key can be extended with 2FA wrappers easily.

## The power

There are some ways developers can extend it to be powerful.

- Backup tools can directly work with uploaded data easily.
- The client can address the file any time with its SHA256 hash.
- The client can XOR split the stream to two different cloud providers lowering risk.
- The client can do striping to two or more different cloud providers doubling bandwidth.
- File cleanup delay can be adjusted to act like a cache or the legal backup.
- File hashes act like page and segment addresses of Intel and AMD process pages.
- Such a setup can work as an in-memory distributed process with optional nvram swap.
- Memory mapped, and swap volumes can speed up frequently accessed files.
- A wrapper can customize authorization and security.
- If you need to scale reading back the same data, we suggest to use a Kubernetes ingress of 2-5 nodes.
- Scaling large scale frequent updates can be solved with an iSCSI Linux cluster making it a distributed machine.

## Examples

The temporary directory is a good candidate to prevent data leaks.
Tmp will be an issue deleting across reboots or with a delay.
You can use `/var/lib` or `/home` for permanent storage.

```
echo test > /tmp/test
echo abc > /tmp/apikey
curl 127.0.0.1:7777/?apikey=abc
curl -X PUT 127.0.0.1:7777/?apikey=abc -T /tmp/test
curl -X POST 127.0.0.1:7777/?apikey=abc -T /tmp/test
curl 127.0.0.1:7777/?apikey=abc
curl 127.0.0.1:7777/f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2.tig
cat /tmp/test | sha256sum | head -c 64
printf "http://127.0.0.1:7777/`cat /tmp/test | sha256sum | head -c 64`.tig"
```
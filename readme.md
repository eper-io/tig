# TIG

Tig is a git alternative to back up your codebase or data.

The design considerations were the following.

- AI generates more code than people.
- Copilots can apply generic code. Author bookkeeping becomes unnecessary.
- Reliability becomes more important with more code and less time to verify.
- It is better to address code with its entire hash than a file name, date, or version.
- Storage is cheaper, simple consistency is more important than disk usage.
- Disk compression logic can solve repetition of blocks easily.
- Change ordering is obsolete. Generative AI works on parallel versions.
- Time stamps are less important, coding is non-linear.
- Stable codebase is important. Hash identifies an entire repo, not a diff.
- Revisions need to be tested and reviewed before use. Who wrote them is obsolete.
- The stable version is a highly utilized version more likely than the latest one.
- Storing more revisions is more important than full push updates of repo history.
- We still need a way to securely iterate through all versions.
- Api key is good enough especially if it can only be set by the owner of the server.
- Api key can be extended with 2FA wrappers and monitoring solutions easily.
- Cleanup logic can solve the case of privacy laws.
- Your data is cleaned up in a period like ten minutes or two weeks by default.
- Answer to a privacy question can be "If you used the site more than two weeks ago, your data is cleared."
- Secondary backups can still iterate and store data for longer keeping the cache container a fixed size.

## The power

There are some ways developers can extend it to be powerful.

- Backup tools can directly work with uploaded data easily.
- The client can address the file any time with its SHA256 hash.
- The client can XOR split the stream to two different cloud providers lowering risk.
- The client can do striping to two or more different cloud providers doubling bandwidth.
- File cleanup delay can be adjusted to act like a cache or the legal backup.
- File hashes act like page and segment addresses of Intel and AMD process pages.
- A simple html [page](https://gitlab.com/eper.io/sat) can build a distributed process leveraging server memory.
- Such a setup can work as an in-memory distributed process with optional nvram swap.
- Memory mapped, and swap volumes can speed up frequently accessed files.
- An off the shelf wrapper can customize authorization and security.
- If you need to scale reading back the same data, we suggest to use a Kubernetes ingress of 2-5 nodes.
- Scaling large scale frequent updates can be solved with an iSCSI Linux cluster making it a distributed machine.
- A simple sha256 on a file or a directory tar or zip can identify an entire version
- tig eliminates external API calls to git and a necessary download of git binaries on each container.
- There is no need of complex protocol binaries of git to check out. It is HTTP.
- tig is ideal for data streaming workloads as a middle tier.
- tig can handle streaming bottlenecks as a result being cleaned up, but handling pushes
- tig cannot force update a push. Any deletion propagates over time giving chance to restore.
- See [example](documentation/tig.sh) to see the power of a code commit generating docker script.
- The hash construct can help to remote load less frequently used libraries or DLLs on Unix/Windows.
- Hash addressing makes it safer to download and run scripts like get.docker.com. You can verify anytime, what ran.

## Examples

The temporary directory is a good candidate to prevent data leaks.
Tmp will be an issue deleting across reboots or with a delay.
You can use `/var/lib`, `/mnt` or `/home` for permanent storage.

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
# Errors, formatting, and random content
curl 127.0.0.1:7777/randomfileunauthorized
uuidgen | sha256sum | head -c 64 | curl --data-binary @- -X POST 'http://127.0.0.1:7777?format=http://127.0.0.1:7777*'
curl -X GET 'http://127.0.0.1:7777?format=http://127.0.0.1:7777*'
# Commit the current directory
tar --exclude .git -c . | curl --data-binary @- -X POST 127.0.0.1:7777/?apikey=abc
zip -r -x '.*' - . | curl --data-binary @- -X POST 127.0.0.1:7777/?apikey=abc
# Do a full backup of the remote repository locally
curl -s 127.0.0.1:7777 | xargs -I {} curl -s 127.0.0.1:7777{} --output .{}
```

The main design decision is to let the client deal with ordering and tagging.
This makes the server side and the protocol simple.
Each repository can contain files from multiple projects.
Any repeated patterns can be compressed at the file system level.

## Storage directory suggestions:

/tmp It cleans up fast, it is sometimes low latency memory based storage.

/usr/lib It is a good choice for executable modules. It is persistent.

/var/log Choose this for persistent data. It is persistent across reboots.

/opt/ Use this for entire solutions. It is persistent.

~/ Use, if you run outside a container without privileges, but you need persistence across reboot.

It is a good idea to delayed delete files setting `cleanup`.

Clients can keep resubmitting them making the system more resilient.

Such systems comply easier with privacy regulations being just a cache not a root storage.

Here is an example to launch tig on ramdisk.

```
mkdir /tmp
mount -t tmpfs -o size=3g tmpfs /tmp
...
```

Here is an example to mount tmpfs into docker.
```
docker run -t -i --tmpfs /tmp:rw,size=2g docker.io/image
...
```

## Usage with proper EFF certificates.

Please review any firewall policies.

```
dnf update
dnf install epel-release
dnf install nginx certbot python3-certbot-apache mod_ssl python3-certbot-dns-digitalocean python3-certbot-dns-digitalocean python3-certbot-nginx
firewall-cmd --permanent --add-port=80/tcp --zone=public
firewall-cmd --permanent --add-port=443/tcp --zone=public
firewall-cmd --reload
certbot certonly --standalone -d example.com
cp /etc/letsencrypt/live/example.com/privkey.pem /etc/ssl/tig.key
cp /etc/letsencrypt/live/example.com/fullchain.pem /etc/ssl/tig.crt
```
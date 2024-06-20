![tig](./documentation/logo.jpeg)

# TIG

Tig is a git alternative to back up your codebase or data.

The design considerations were the following.

- AI generates more code than people.
- Code duplication is a huge cost reduction opportunity in data lakes.
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
- If the vast majority of the systems is on auto clean, finding the root personal data is easy.
- Your data is cleaned up in a period like ten minutes or two weeks by default.
- Answer to a privacy question can be "If you used the site more than two weeks ago, your data is cleared."
- Secondary backups can still iterate and store data for longer keeping the cache container a fixed size.

## Security

We use an API key for internal corporate networks

- Lost tokens and passwords are an issue already.
- An api key is a good way to reliably separate apps.
- If your browser has issues with api keys, are you sure it does not have an issue with bearer tokens?
- Your organization may enforce a hardware security module or trusted platform module for compliance.
- Can you verify the hardware path and the integrity of a manufactured lot of HSM or TPM anyway? 
- We suggest adding 2FA here & any AI monitoring tool based on your organization's standards.
- The reason is that security comes at costs and responsible CIOs insist on full control on these.
- The apikey on disk is safer than the in memory variable due to the mutability and observability.
- Make sure the logic cannot write small root files like apikey, but 64 byte SHA256.
- SHA512 may be an option to add as a competitive edge for easy money compared to the free download.
- Check the downloaded codebase periodically as ransomware can tamper with memory, disk storage, or chipset buses.
- Implementations that do not require backups are safer without an apikey.
- The logic deletes unused items periodically for safety and privacy. It is ideal for self-healing demos.

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
- You can use scaling with our Mitosis algorithm, the cloud investor's and CFO's favorite dream.
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
- Distributed databases are easy to merge with hash granularity similar to commit sizes.

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

## Key Value Store

Using tig as a traditional key value store is discouraged. The reason is that hashes ensure that the data is cryptographically secure.

- Use a tree of hashed segments to represent large files or database snapshots with hashes as pointers.
- Change just the index nodes on updates.
- Only the root snapshot key requires a value stored by a key in the traditional sense.
- Normally we just `PUT` the data, and refer to it later with its hash.
- We use the hash of the key instead and `PUT` in the path with the data as body to store a key value pair.
- The indirection indicates that this is a key value pair, not raw data. This allows the key to still be used as data and referred by its own hash later. The hash of a key hash will not collide wit any other hash.
- The formatted key returned can be used later to update the key value pair as many times as desired.
- The key hash will never change.

Example

```
% echo key | curl -X PUT --data-binary @- 'http://127.0.0.1:7777?format=http://127.0.0.1:7777*'
http://127.0.0.1:7777/a7998f247bd965694ff227fa325c81169a07471a8b6808d3e002a486c4e65975.tig
% echo abc | curl -X PUT --data-binary @- 'http://127.0.0.1:7777/a7998f247bd965694ff227fa325c81169a07471a8b6808d3e002a486c4e65975.tig?format=http://127.0.0.1:7777*'
http://127.0.0.1:7777/a7998f247bd965694ff227fa325c81169a07471a8b6808d3e002a486c4e65975.tig
% curl http://127.0.0.1:7777/a7998f247bd965694ff227fa325c81169a07471a8b6808d3e002a486c4e65975.tig
abc
% echo def | curl -X PUT --data-binary @- 'http://127.0.0.1:7777/a7998f247bd965694ff227fa325c81169a07471a8b6808d3e002a486c4e65975.tig?format=http://127.0.0.1:7777*'
http://127.0.0.1:7777/a7998f247bd965694ff227fa325c81169a07471a8b6808d3e002a486c4e65975.tig
% curl curl http://127.0.0.1:7777/a7998f247bd965694ff227fa325c81169a07471a8b6808d3e002a486c4e65975.tig
def
```

## Bursts

Oftentimes we need more data that is scattered around other files. A typical example is a simple columnar index of a data table kept updated with insertions.

Burst are similar to DRAM bursts or rather scatter gather DMA, when data is fetched and concatenated from multiple addresses.

```
% printf abc | curl -X PUT --data-binary @- 'http://127.0.0.1:7777?format=http://127.0.0.1:7777*' >/tmp/burst.txt
% echo >>/tmp/burst.txt
% printf def | curl -X PUT --data-binary @- 'http://127.0.0.1:7777?format=http://127.0.0.1:7777*' >>/tmp/burst.txt
% echo >>/tmp/burst.txt
% printf ghi | curl -X PUT --data-binary @- 'http://127.0.0.1:7777?format=http://127.0.0.1:7777*' >>/tmp/burst.txt
% echo >>/tmp/burst.txt
% cat /tmp/burst.txt
/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.tig
/cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34.tig
/50ae61e841fac4e8f9e40baf2ad36ec868922ea48368c18f9535e47db56dd7fb.tig
% cat /tmp/burst.txt | curl -X PUT --data-binary @- 'http://127.0.0.1:7777?format=*'
% curl 'http://127.0.0.1:7777/1bc742e60c70acf19ff57998fb85e129a69396526a3c7fc114d2df4acb54248e.tig'
/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.tig
/cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34.tig
/50ae61e841fac4e8f9e40baf2ad36ec868922ea48368c18f9535e47db56dd7fb.tig
% curl 'http://127.0.0.1:7777/1bc742e60c70acf19ff57998fb85e129a69396526a3c7fc114d2df4acb54248e.tig?burst=1'
abcdefghi
```

## Storage directory suggestions:

`/tmp` and any `tmpfs` : It cleans up fast, it is sometimes low latency memory based storage.

`/usr/lib` : It is a good choice for executable modules. It is persistent.

`/var/log` : Choose this for persistent data. It is persistent across reboots.

`/opt/` : Use this for entire solutions. It is persistent.

`~/` : Use, if you run outside a container without privileges, but you need persistence across reboot.

It is a good idea to perform delayed delete on files setting `cleanup`.

Clients can keep resubmitting them making the system more resilient. This resets the timer.

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
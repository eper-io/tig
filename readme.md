![tig](./documentation/logo.jpeg)

# TIG

Tig is a simple in-memory storage utility for code, data, and vectors.
It started as a git alternative for your codebase or data, but it grew in feature set.

It is targeted for the following use cases.
- High reliability infrastructure like pipelines, industrial applications
- Low cost, low maintenance infrastructure
- Frequently audited security infrastructure
- Embedded logging, black boxes
- Security logging, in-house backups
- In-memory low latency databases
- Data streaming, delayed streaming to the cloud
- Temporary Kubernetes storage layer
- A defense in depth layer next to Redis, Memcached, Zookeeper

Memory management giving an alternative to garbage collection
- Operating systems leverage the VM hardware support of Intel and ARM
- Traditional Unix & Windows required manual malloc and free
- COM, Rust methods relied on complex reference counting
- Java, .NET & Go use a randomized delayed garbage collection
- We use a better approach with reliable timed deletion
- We do not need reference counting as a result, just keep alive calls
- We require the owner to periodically read or write the block
- This allows the owner to use the regular pointer tree to scan the structures
- Blocks used rarely can be identified and offloaded to cheaper storage
- This approach works in both embedded and data center environments
- It is reliable and predictable, leaks can be found with each scan
- Issues can be identified by the owner debugging their code
- There are no pointer and reference counting logic duplications

The design considerations were the following.

- AI generates more code than people.
- Storing data by its hash is a huge cost reduction opportunity in data lakes due to duplications.
- Copilots can apply generic code. Author bookkeeping of git becomes unnecessary.
- Reliability achieved by storing with hash is important with more code and less time to verify.
- It is safer to address code with its entire hash than a file name, date, or version.
- Storage is cheaper, simple consistency is more important than perfectly optimized disk usage.
- Duplications are the number one disk usage optimization technique.
- Hashing chunks of an entire file solves repetition of blocks easily returned as a burst read.
- Generative AI works on parallel versions. Change ordering is obsolete.
- Time stamps are less important, coding is non-linear.
- A stable codebase is important. A hash identifies an entire repo, not a diff.
- All revisions must tested and reviewed before use. Who wrote them is obsolete with AI.
- The stable version is a highly utilized version more likely than the latest one.
- Storing all revisions is more important than full push updates of repo history.
- We may still need a way to securely iterate through all versions to back up by admins.
- Api key is good enough for admins, especially if it can only be set by the owner of the server.
- Api key can be extended with 2FA wrappers and monitoring solutions easily.
- The retention and cleanup logic solves the major requirements of privacy laws.
- If the system is on auto clean, finding the source of personal data is easy.
- Your data is cleaned up in a period like ten minutes or two weeks by default.
- Most systems are on auto clean. Use the last backup to retrieve or delete private data.
- Answer to a privacy question can be any data older than two weeks is deleted.
- Secondary backups can still iterate and store data for longer.
- The cleanup logic keeps the most expensive internet facing containers fixed in size.
- We favor streaming workloads just limiting the buffer size used.
- Streaming with smaller blocks allows prefetching content in advance for reliability and security.
- We provide clustering behavior with any replicas handled in applications.
- Clustering is balanced, when hashes identify the blocks.
- We released the code in the civilian control friendly Creative Commons 0 license.
- CC0 is more suitable for research organizations focused on patents.
- We are also considering releasing it under the Apache license.
- Apache is better for SaaS providers focused on a robust codebase due to the size of the community.

## Security

You can use an API key for internal corporate networks to protect administrative features.

- Lost tokens and passwords are an issue already, keys are acceptable.
- An api key is a good way to reliably separate apps and mark legally private access.
- If your browser has issues with api keys, it probably has an issue with bearer tokens.
- Your organization may use a hardware security or trusted platform module for compliance.
- It is difficult to verify the integrity of a manufactured lot of HSM or TPM hardware.
- We suggest adding 2FA here & any AI monitoring tool based on your organization's standards.
- We pass responsibility to the integrator to avoid a bouncy castle of patch work.
- The reason is that responsible CIOs insist on full & complete control.
- The apikey on disk is safer than the in memory variable due to the mutability and observability.
- We make sure the logic cannot write any other files than the 64 byte SHA256 with tig extension.
- SHA512 may be an option as a competitive edge for a paid option compared to the free download.
- Check and audit the downloaded codebase periodically.
- Ransomware can tamper with memory, disk storage, or chipset buses. Frequent audits help.
- Implementations that do not require backups are safer without an apikey.
- If there is no api key, then admin access is impossible without the OS.
- The logic deletes unused items periodically for safety and privacy.
- This feature makes it ideal for self-healing demos.
- Make sure to limit physical access to cloud instances to protect the data.
- Try to eliminate SSH, console, extensions, unnecessary updates, etc.
- You can even fetch public operating system update binaries through unencrypted http.
- Try something like `http://example.com/5fe8...1ec.tig`.
- It is secure, if you verify the hash `5fe8...1ec` downstream on the client box.
- This power eliminates any man-in-the-middle attack possibilities.
- Such threats are due to the design of TLS being opaque and encrypted for the most important files.
- You do not know what is transmitted. Why would you encrypt public updates?
- Governments can monitor the channel for security.
- The code integrity of the corporate networks can be ensured better with traffic monitoring.
- This integrity was the power of early DOS and Windows systems that partly made Microsoft so successful.
- We eliminate external API calls to git and a necessary download of git binaries on each container.
- There is no need of complex protocol binaries of git to check out. It is HTTP.
- tig cannot force update a push like git. Any deletion propagates over time giving a chance to restore.

## The power

There are some ways developers can extend it to be powerful.

- Backup tools can directly work with the uploaded data easily having it in the file system.
- The client can address the data file any time with its SHA256 hash.
- The filtered SHA256 hashes may be used as mining data for some crypto currencies generating revenue.
- The client can XOR split the stream to two different cloud providers lowering privacy risks.
- The client can do striping to two or more different data centers doubling bandwidth.
- File cleanup delay can be adjusted to act like a cache or the legal backup.
- We tested 100 ms nearby and 500 ms latency to continental cloud regions.
- File hashes act like page and segment addresses of Intel and AMD process pages.
- Such an arrangement helps to create distributed memory based processes.
- A simple html [page](https://gitlab.com/eper.io/sat) can build a distributed process.
- It is leveraging server memory using the tig calls with unlimited possibilities.
- A process with distributed memory can span across servers.
- Some scenarios are serverless, gaming, and GenAI batch workloads at scale.
- Second, minute, day, and week retention of remote memory are able to run workloads like a GC heap.
- The setup can work as an in-memory distributed process with optional disk swap.
- Memory mapped, and swap volumes can speed up frequently accessed files but provide more space.
- An off the shelf wrapper can customize authorization and security. Try Cloudflare.
- If you need to scale, we suggest to use a Kubernetes ingress of 2-5 nodes.
- You can use scaling with our Mitosis algorithm, the cloud investor's and CFO's best dream.
- Mitosis uses containers with a lifetime.
- Mitosis creates new containers, if the work done to lifetime percentage exceeds the normal.
- Handling a large bandwidth input can be solved with a distributed iSCSI Linux cluster.
- A simple SHA256 on a file or a directory tar or zip can identify an entire version.
- tig is ideal for data streaming workloads as a middle tier.
- tig can handle streaming bottlenecks as a result being cleaned up.
- See the power of a code commit generating script int the next line
- `echo curl https://e.com$(tar -c . | curl --data-binary @- -X PUT https://e.com) | tar -x`
- The hash construct can help to remote load less frequently used libraries like DLLs.
- Hash addressing makes it safer to download and run scripts like get.docker.com.
- You can verify anytime, what ran by hashing the entire launch payload.
- Distributed databases are easy to merge with hash granularity similar to commit sizes.
- It is super simple to use the same backend for critically distinct workloads.
- Separate workloads can share data with the same hash to save on memory space.
- Repetitive patterns can be compressed at the level of the burst requests.

## Examples

### Read-only non-volatile hash based storage

We add an item stored by its hash. We won't be able to update or delete it until the system cleanup.

```
% echo 123 | curl -X PUT --data-binary @- http://127.0.0.1:7777
/181210f8f9c779c26da1d9b2075bde0127302ee0e3fca38c9a83f5b1dd8e5d3b.tig
% echo 123 | curl -X POST --data-binary @- http://127.0.0.1:7777
/181210f8f9c779c26da1d9b2075bde0127302ee0e3fca38c9a83f5b1dd8e5d3b.tig
% curl http://127.0.0.1:7777/181210f8f9c779c26da1d9b2075bde0127302ee0e3fca38c9a83f5b1dd8e5d3b.tig
123
% echo 123 | sha256sum | head -c 64 
181210f8f9c779c26da1d9b2075bde0127302ee0e3fca38c9a83f5b1dd8e5d3b
% printf "http://127.0.0.1:7777/`echo 123 | sha256sum | head -c 64`.tig"
http://127.0.0.1:7777/181210f8f9c779c26da1d9b2075bde0127302ee0e3fca38c9a83f5b1dd8e5d3b.tig
% curl -X DELETE http://127.0.0.1:7777/181210f8f9c779c26da1d9b2075bde0127302ee0e3fca38c9a83f5b1dd8e5d3b.tig
% curl http://127.0.0.1:7777/181210f8f9c779c26da1d9b2075bde0127302ee0e3fca38c9a83f5b1dd8e5d3b.tig
123
% echo 245 | curl -X PUT --data-binary @- 'http://127.0.0.1:7777/181210f8f9c779c26da1d9b2075bde0127302ee0e3fca38c9a83f5b1dd8e5d3b.tig?format=http://127.0.0.1:7777*'
% curl http://127.0.0.1:7777/181210f8f9c779c26da1d9b2075bde0127302ee0e3fca38c9a83f5b1dd8e5d3b.tig
123
```

### Errors, formatting, and random content

```
% curl 'http://127.0.0.1:7777/randomfileunauthorized'
% echo 123 | curl -X PUT --data-binary @- 'http://127.0.0.1:7777?format=http://127.0.0.1:7777*'
http://127.0.0.1:7777/181210f8f9c779c26da1d9b2075bde0127302ee0e3fca38c9a83f5b1dd8e5d3b.tig
% uuidgen | curl -X PUT --data-binary @- 'http://127.0.0.1:7777?format=http://127.0.0.1:7777*'
http://127.0.0.1:7777/a878438bf5b7e257cbd3bca5c5f1c1cbac95b8e98f2993764c9c43a87fe3bb69.tig
% uuidgen | curl -X PUT --data-binary @- 'http://127.0.0.1:7777?format=http://127.0.0.1:7777*'
http://127.0.0.1:7777/ff7a1618e595344513870ffac1c11ff92a4902fe47ef9947f93301c73a03183f.tig
```

### Commit the current directory into a store

```
tar --exclude .git -c . | curl --data-binary @- -X PUT 'http://127.0.0.1:7777'
zip -r -x '.*' - . | curl --data-binary @- -X POST 'http://127.0.0.1:7777'
% tar --exclude-from=.gitignore -czv . | curl --data-binary @- -X PUT 'http://127.0.0.1:7777'
a .
a ./documentation
a ./go.mod
a ./LICENSE
a ./.do
a ./Dockerfile
a ./readme.md
a ./.gitignore
a ./.gitlab-ci.yml
a ./main.go
a ./.do/deploy.template.yaml
a ./documentation/tig.yaml
a ./documentation/logo.png
a ./documentation/logo.jpeg
a ./documentation/commit.sh
/10f21af8baa6980bcd0e26ac91822c6a8b9face9ce568aacbed422b36a08e54e.tig
% curl http://127.0.0.1:7777/10f21af8baa6980bcd0e26ac91822c6a8b9face9ce568aacbed422b36a08e54e.tig | tar -t
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0./
./documentation/
./go.mod
./LICENSE
./.do/
./Dockerfile
./readme.md
./.gitignore
./.gitlab-ci.yml
./main.go
./.do/deploy.template.yaml
./documentation/tig.yaml
./documentation/logo.png
./documentation/logo.jpeg
./documentation/commit.sh
100  420k    0  420k    0     0  20.4M      0 --:--:-- --:--:-- --:--:-- 21.5M
```

### Do a full backup of the remote repository locally. This is possible, but discouraged due to security limitations.

```
echo abc >/tmp/apikey
curl -s 'http://127.0.0.1:7777?apikey=abc' | xargs -I {} curl -s 127.0.0.1:7777{} --output .{}
```

### A better approach is to hide the latest snapshot behind a secret key on the server.

```
while true; do sleep 60; tar -czv './data' | curl -X PUT http://127.0.0.1:7777/5d26733ace0280e46ee1f8dbf3bf40f9144668a4ef616e608970c968db418667.tig; done
```

The main design decision is to let the client deal with ordering and tagging.
This makes both the client and server side simple. The protocol is easy to audit.
Each repository can contain files from multiple projects.
This helps with corporate wide dependencies, and cost reduction.
Any repeated patterns can be compressed at the file system level.

## Key Value Store

You primarily address blocks by the hash of the value. We ensure that once a block is stored by its hash, that address remains immutable.

Using the system as a traditional key value store is a minor feature. The reason is that hashes ensure that the data is cryptographically secure. Once we store by the hash of a key instead of the hash of the value, the value can change.

These are the possibilities of using tig as a key value store.

- Use a burst of hashed segments of large files or database snapshots with hashes as pointers.
- Change just the index nodes on updates.
- Only the root snapshot key requires a value stored by a key.
- We just `PUT` the data, and refer to it with the hash of the value in the non-key-value case.
- We use the hash of the key in case of the key-value case. A key is read-write.
- We specify the key with its SHA256 hash in the path.
- We `HTTP PUT` to this hashed key path with the data as body to store a key value pair.
- The difference is that R/W keys have a unique path compared to the read only mode of root `/`.
- The presence of the path at `HTTP PUT` indicates that this is a key value pair, not raw data.
- The hash of a key may collide with any previus storage of that key as hash.
- Use the hash of the hash of a key to resolve this collision of values.
- If a data file has been stored by its hash, you cannot overwrite anymore as a key value pair.
- The key hash returned on success can be used to update the key value pair many times.
- The key hash will never change.
- Keep the value size below the block size of the file system.
- Many operating system and kernel specific synchronization issues can be avoided with small values. 

Example

```
% uuidgen | sha256sum 
e410f72ef5d487f68543eb898ac2e9d4ddfed0b824f28f481a63ea1dca8a383a  -
% echo 123 | curl -X PUT --data-binary @- 'http://127.0.0.1:7777/e410f72ef5d487f68543eb898ac2e9d4ddfed0b824f28f481a63ea1dca8a383a.tig?format=http://127.0.0.1:7777*'
http://127.0.0.1:7777/e410f72ef5d487f68543eb898ac2e9d4ddfed0b824f28f481a63ea1dca8a383a.tig
% curl http://127.0.0.1:7777/e410f72ef5d487f68543eb898ac2e9d4ddfed0b824f28f481a63ea1dca8a383a.tig
123
% echo 456 | curl -X PUT --data-binary @- 'http://127.0.0.1:7777/e410f72ef5d487f68543eb898ac2e9d4ddfed0b824f28f481a63ea1dca8a383a.tig?format=http://127.0.0.1:7777*'
http://127.0.0.1:7777/e410f72ef5d487f68543eb898ac2e9d4ddfed0b824f28f481a63ea1dca8a383a.tig
% curl http://127.0.0.1:7777/e410f72ef5d487f68543eb898ac2e9d4ddfed0b824f28f481a63ea1dca8a383a.tig
456
% curl -X DELETE http://127.0.0.1:7777/e410f72ef5d487f68543eb898ac2e9d4ddfed0b824f28f481a63ea1dca8a383a.tig
/e410f72ef5d487f68543eb898ac2e9d4ddfed0b824f28f481a63ea1dca8a383a.tig
% curl http://127.0.0.1:7777/e410f72ef5d487f68543eb898ac2e9d4ddfed0b824f28f481a63ea1dca8a383a.tig
% curl -X DELETE http://127.0.0.1:7777/e410f72ef5d487f68543eb898ac2e9d4ddfed0b824f28f481a63ea1dca8a383a.tig
% curl http://127.0.0.1:7777/e410f72ef5d487f68543eb898ac2e9d4ddfed0b824f28f481a63ea1dca8a383a.tig
```

## Bursts

Oftentimes we need more data that is scattered around other files. A typical example is a simple columnar index of a data table kept updated with insertions.

Bursts are similar to DRAM bursts or scatter gather DMA, when data is fetched and concatenated from multiple addresses.

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

## Synchronization

We rely on file system level synchronization such as O_EXCL. We do not use processor test and set (TAS) or (XCHG) instructions considered expensive for memory buses on shared cores.
Setting a variable only, if it was not set is good enough for synchronization most use cases such as creating a mutex/semaphore for lambda function runs.

The following call will only return the path, if we successfully set the specified file used as an exclusive slot. It will return empty, if it is used. We should retry or choose another key.

```
echo 123 | curl -X 'PUT' --data-binary @- 'http://127.0.0.1:7777/7574284e16a554088122dcd49e69f96061965d7c599f834393b563fb31854c7f.tig?setifnot=1'
```

The following call will append to the file using file system level synchronization just like `>>log.txt`. This helps with logs and traces. Use a random key path for proper behavior.

```
echo We added one more file. | curl -X 'PUT' --data-binary @- 'http://127.0.0.1:7777/7574284e16a554088122dcd49e69f96061965d7c599f834393b563fb31854c7f.tig?append=1'
```

## Authorization

Oftentimes data needs to be provided as a read-only block for some, and read-write block for other users.

Here is an example implementation. We use a burst block that can be written pointed to a block identified by its hash. These are by definition read-only. Readers only have access to the readable hash, not the writable one.

```
echo This is a read-only block. | curl -X 'PUT' --data-binary @- 'http://127.0.0.1:7777'
/abb240c53a62c037d5997d3e0db5aa9d30a6e2264b50f32bb01c253b27523948.tig
printf /abb240c53a62c037d5997d3e0db5aa9d30a6e2264b50f32bb01c253b27523948.tig | curl -X 'PUT' --data-binary @- 'http://127.0.0.1:7777/971dc2a3b9c2774f7b6d4fbb72984bd1407ca6cc2e9e1b7c581f6aaf4199918c.tig'
/971dc2a3b9c2774f7b6d4fbb72984bd1407ca6cc2e9e1b7c581f6aaf4199918c.tig
curl 'http://127.0.0.1:7777/971dc2a3b9c2774f7b6d4fbb72984bd1407ca6cc2e9e1b7c581f6aaf4199918c.tig'
/abb240c53a62c037d5997d3e0db5aa9d30a6e2264b50f32bb01c253b27523948.tig
curl 'http://127.0.0.1:7777/971dc2a3b9c2774f7b6d4fbb72984bd1407ca6cc2e9e1b7c581f6aaf4199918c.tig?burst=1'
This is a read-only block.
```

Let's modify the mutable-read write block using bursts.

```
echo This is a second read-only block. | curl -X 'PUT' --data-binary @- 'http://127.0.0.1:7777'
/29fed4c1dcde487e1216f525f4faf6e5c9d03fb4ae74b6f664684df5e228af3a.tig
printf /29fed4c1dcde487e1216f525f4faf6e5c9d03fb4ae74b6f664684df5e228af3a.tig | curl -X 'PUT' --data-binary @- 'http://127.0.0.1:7777/971dc2a3b9c2774f7b6d4fbb72984bd1407ca6cc2e9e1b7c581f6aaf4199918c.tig'
/971dc2a3b9c2774f7b6d4fbb72984bd1407ca6cc2e9e1b7c581f6aaf4199918c.tig
curl 'http://127.0.0.1:7777/971dc2a3b9c2774f7b6d4fbb72984bd1407ca6cc2e9e1b7c581f6aaf4199918c.tig?burst=1'
This is a second read-only block.
```

Verify and observe that the read-only link cannot be changed or deleted.

```
echo This is a third read-only block. | curl -X 'PUT' --data-binary @- 'http://127.0.0.1:7777/abb240c53a62c037d5997d3e0db5aa9d30a6e2264b50f32bb01c253b27523948.tig'
curl 'http://127.0.0.1:7777/abb240c53a62c037d5997d3e0db5aa9d30a6e2264b50f32bb01c253b27523948.tig'
This is a read-only block.
curl -X 'DELETE' 'http://127.0.0.1:7777/abb240c53a62c037d5997d3e0db5aa9d30a6e2264b50f32bb01c253b27523948.tig'
curl 'http://127.0.0.1:7777/abb240c53a62c037d5997d3e0db5aa9d30a6e2264b50f32bb01c253b27523948.tig'
This is a read-only block.
```

## Explanation for CUDA professionals

Our solution interestingly ended up with the same patterns as CUDA.

In CUDA, a constant is a variable stored in constant memory, accessible by all threads but with limited size (64KB per multiprocessor).  Access is faster than global memory but slower than registers or shared memory.  A texture, on the other hand, is stored in texture memory, optimized for spatial locality. Access patterns significantly impact performance; textures excel with coherent reads, while constants are best for small, frequently accessed data that's the same for all threads.

Our solution allows you to store read-only hash indexed blocks easily whether you are in a browser, Win32 process, Unix process, Apple Metal, or a Docker core running some CUDA kernels. This is what happens, when you push a block. It can propagate easily knowing that it will not change.

If you need larger read-only blocks, you can use the burst functionality.

When you need to read-write data, then you can write key value pairs with snapshots in them. These can be some small data or pointers to other blocks for database logic or graphics frames.

Read-only hashed storage is ideal for artificial intelligence models, where reliability and security requires stability and complexity prevents scanning the weights all the time.

## Storage directory suggestions:

`/data` is the default location. It must exist, otherwise we fall back to `/tmp` 

`/tmp` and any `tmpfs` : It cleans up fast, it is sometimes low latency memory based storage.

`/usr/lib` : It is a good choice for executable modules. It is persistent.

`/var/log` : Choose this for persistent data. It is persistent across reboots.

`/opt/` : Use this for entire solutions. It is persistent.

`~/` : Use, if you run outside a container without privileges with the need of persistence.

It is a good idea to perform delayed delete on files setting a small cleanup period.

Clients can keep resubmitting or accessing them making the system more resilient.

Updates and queries reset the timer. This is similar to the busy flag of pages in traditional Intel and ARM processors capable of virtual memory handling. The timer restarts on existing data when we restart the container. Old files are simply deleted.

A standard keep alive logic is scanning a new line separated list of files and directories.
This can happen every five minutes if the cleanup period is ten minutes.
Recursive scanning allows a keep alive logic for distinct directory trees, or roots.
The traffic also ensures that the files are valid. It can be used for billing.

Such systems comply easier with privacy regulations. It is just a temporary cache not a root storage. It makes the system a router with delay rather than a database or file storage.

Here is an example to launch tig on ramdisk.

```
mkdir /data
mount -t tmpfs -o size=24g tmpfs /data
...
```

Here is an example to mount tmpfs into docker.
```
docker run -t -i --tmpfs /data:rw,size=4g tig:latest
...
```

The last one specifies a Docker example to map some memory.
```
`docker run -d --mount type=tmpfs,destination=/data,tmpfs-size=4g tig:latest`
```

## Usage with proper EFF certificates.

Please review any firewall policies before switching to TLS and SSL certificates.

This is an example with the EFF's free `letsencrypt` solution.

We suggest using a paid provider like `zerossl.com` or your cloud account.
They were proven to be more widely accepted by browsers and operating systems.

```
dnf update
dnf install epel-release
dnf install nginx certbot python3-certbot-apache mod_ssl python3-certbot-dns-digitalocean python3-certbot-dns-digitalocean python3-certbot-nginx
firewall-cmd --permanent --add-port=443/tcp --zone=public
firewall-cmd --reload
certbot certonly --standalone -d example.com
cp /etc/letsencrypt/live/example.com/privkey.pem /etc/ssl/tig.key
cp /etc/letsencrypt/live/example.com/fullchain.pem /etc/ssl/tig.crt
```

## Clustering

- We can set the cluster address in `main.go` to run multiple instances in parallel.

- These instances will share the workload in a random way.

- When an instance receives an unknown hash it queries the cluster and forwards the request.

- This kind of implicit load balancing makes it simple.

- Querying is done using DNS. This can be a list of A or CNAME records.

- A K8S headless service can expose the addresses of all active pods.

- A K8S headless service has a different local .internal name. We use InsecureSkipVerify=true for these cluster local calls over the external TLS API.

- We forward requests to all active pods. This may add some latency.

- You can also set a flag to use a tree of tig containers adding the local address to the leaf.

- See the code for details.

## Benchmark

We achieved the minimum practical latency of sustained 13 ms on an Apple Mac Studio. This is not bad for a golang codebase.

Better performance could be achieved by C or C++ LLM transformations, better dos handling and direct UDP implementation.

```
while true; do uuidgen | time curl http://127.0.0.1:7777`time curl -X 'PUT' --data-binary @- 'http://127.0.0.1:7777'`; done
```

There are a few hints how to optimize the code for the best performance.

Use a memory mapped drive as the data directory. Ideally this is tmpfs.

Tmpfs and ext4 both have limitations of minimum file size of 4K on Intel and 8K on ARM. Try to use bigger buffers as a result.

If you have to use very small data bits, then it is better to keep updating the same file using a key value pair instead of hashed storage.

10 minute is a good retention period for demos, 1 GBps is a common cloud bandwidth. These were used to set the default file size.

The benchmarks are limited due to the need to read the entire stream to maintain hashes and find the right location.
This helps on the other hand with a robust security, especially for sensitive code and binaries.

## Strategy

- Scheduling cleanups at startup covers migrations due to hardware upgrades.

- Do not rely on cleanup to cover any restart issues.

- Crashes or hangs should be fixed first instead.

- We keep the code less than a few hundred lines to be easy to audit.

- Cluster forwarding would normally use a UDP broadcast or multicast on regular nodes.

- Since we may use K8S we opt for querying a DNS address specified by a headless service.

- The HTTP forwarding logic makes the solution very flexible.

- Fully utilizing standalone GPU, memory, and disk clusters is an opportunity.

- Clusters can scale using pod termination signals, an additional API, or lifetime.

- We decided to implement cluster balancing with a lifetime to offload & terminate.

- Terminating with a lifetime is very deterministic and secure way to offload and scale in & out.

- Use a cluster of two nodes or more to implement cluster balancing.

- The ever replacing dynamism of pods with lifetime makes the solution flexible and scalable.

- We publish the codebase supporting multiple providers.

- We do this to increase the negotiation power of the community 

- The latest codebase is always at [https://gitlab.com/eper.io/tig](https://gitlab.com/eper.io/tig)

- There is a mirror at [https://github.com/eper-io/tig](https://github.com/eper-io/tig)

## Kubernetes

You can run tig as a cluster deployment with multiple pods on Kubernetes.

Here is an example yaml file that we tested with Amazon EKS.

Generate a code file running tig on example.com.

- You can either use Letsencrypt or zerossl as described above to get TLS files.
- Place `private.key` into `/etc/ssl/tig.key`
- Place `certificate.crt`, `ba_bundle.crt` into `/etc/ssl/tig.crt`
- Run the script below to commit and get the command to include in your Kubernetes yaml file .
```bash
DATAGET=https://example.com DATASET=https://example.com ./documentation/commit.sh
```

```yaml
# Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tig-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: tig-app
  template:
    metadata:
      labels:
        app: tig-app
    spec:
      containers:
      - name: www-tig-app
        image: golang:1.19.3
        command: ["/bin/sh"]
        args: ["-c", "cd /go/src;curl https://example.com/1915.....c9d5.tig | tar -x;go run main.go"]
        ports:
        - containerPort: 443
        volumeMounts:
        - name: tmpfs-volume
          mountPath: /data
      volumes:
      - name: tmpfs-volume
        emptyDir:
          medium: Memory
          sizeLimit: 2Gi
---

# Service
apiVersion: v1
kind: Service
metadata:
  name: tig-app
spec:
  type: LoadBalancer
  selector:
    app: tig-app
  ports:
    - name: https
      protocol: TCP
      port: 443
      targetPort: 443

---

# Headless Service
apiVersion: v1
kind: Service
metadata:
  name: tig-app-headless
spec:
  type: ClusterIP
  clusterIP: None
  selector:
    app: tig-app
  ports:
    - name: https
      protocol: TCP
      port: 443
      targetPort: 443

---

# Ingress for secure tig service
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: https-tig-app
  annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/ssl-passthrough: "true"
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
spec:
  rules:
  - host: www.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: tig-app
            port: 
              number: 443
```

## Regulatory

Regulatory questions may arise, if the cluster does not have an apikey set.
The system can be treated as a router in this case.
The deletion delay can be lowered.

We suggest the following approach to law enforcement and network security officers.
A smaller period for delayed deletion forces an attacker to use a keep alive logic.
They will need to scan or move the data regularly.
This generates network traffic.
Malicious or illegal packets can be scanned with the regular monitoring toolset.
This keeps monitoring outside in the network.

The regular corporate wide certificate authority method allows internal packet scanning.

We advise against changing the operating system environment to check the packets in place.
Do not open any backdoors into your storage environment as it may allow hackers to plant ransomware.
Any issues may question the data integrity during a litigation.
Any officials opening backdoors in civilian systems may be subject to referral to military police and potential war crimes.

Network scanning allows quarantine and a reliable operation without backdoors exploited by outsiders.

Certain jurisdictions may fall outside the USA cryptography regulations allowing less secure encryption only. Please follow up with your local legal professional.

## Logo

The logo was inspired by the tea clipper. They represented the pinnacle of sailing ship design, combining sleek hulls, tall masts, and enormous sail area to achieve remarkable speeds.
The term "clipper" comes from the word "clip," meaning to move swiftly. These ships were designed to "clip" along at high speeds, regularly achieving 16-18 knots - extremely fast for sailing vessels of that era.

## TODO

- tig was actually a quick idea. It is not really a `git` clone anymore. We could rename this to `storage` or even better `router` that reflects the behavior. It is a timed router or RAM cache.
- Make `InsecureSkipVerify` adjustable for public internet use outside corporate networks.

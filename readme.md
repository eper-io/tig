![tig](./documentation/logo.jpeg)

# TIG

Tig is a git alternative to back up your codebase or data.

The design considerations were the following.

- AI generates more code than people.
- Storing by hash is a huge cost reduction opportunity in data lakes due to duplications.
- Copilots can apply generic code. Author bookkeeping becomes unnecessary.
- Reliability storing by hash is more important with more code and less time to verify.
- It is safer to address code with its entire hash than a file name, date, or version.
- Storage is cheaper, simple consistency is more important than perfectly optimized disk usage.
- Hashing chunks of an entire file solves repetition of blocks easily returned as a burst read.
- Change ordering is obsolete. Generative AI works on parallel versions.
- Time stamps are less important, coding is non-linear.
- A stable codebase is important. A hash identifies an entire repo, not a diff.
- All revisions must tested and reviewed before use. Who wrote them is obsolete with AI.
- The stable version is a highly utilized version more likely than the latest one.
- Storing all revisions is more important than full push updates of repo history.
- We may still need a way to securely iterate through all versions to back up by admins.
- Api key is good enough for admins, especially if it can only be set by the owner of the server.
- Api key can be extended with 2FA wrappers and monitoring solutions easily.
- The retention and cleanup logic solves the case of privacy laws.
- If the vast majority of the systems is on auto clean, finding the source of personal data is easy.
- Your data is cleaned up in a period like ten minutes or two weeks by default.
- Answer to a privacy question can be "If you used the site more than two weeks ago, your data is deleted."
- Secondary backups can still iterate and store data for longer keeping the cache container size fixed.
- Most systems are on auto clean. Use the last backup to retrieve or delete private data.
- We favor streaming workloads limiting the buffer size used.
- Streaming with smaller blocks allows prefetching content in advance for reliability and security.
- We require some clustering behavior with any replicas handled in applications.
- Clustering is balanced, when hashes identify the blocks.
- We also released first under Creative Commons 0 license. This is better suitable for research organizations focused on patents.
- Creative Commons also sounds like Civilian Control to us.
- We are also considering releasing tig under the Apache license. This is better for SaaS providers focused on a robust codebase.

## Security

You can use an API key for internal corporate networks to protect administrative features.

- Lost tokens and passwords are an issue already.
- An api key is a good way to reliably separate apps and mark legally private access.
- If your browser has issues with api keys, it has an issue with bearer tokens, too.
- Your organization may separately enforce a hardware security module or trusted platform module for compliance.
- It is difficult to verify the integrity of a manufactured lot of HSM or TPM hardware.
- We suggest adding 2FA here & any AI monitoring tool based on your organization's standards.
- The reason for passing responsibility is that responsible CIOs insist on full & complete control.
- The apikey on disk is safer than the in memory variable due to the mutability and observability.
- Make sure the logic cannot write any other files than the 64 byte SHA256 with tig extension.
- SHA512 may be an option as a competitive edge for a paid option compared to the free download.
- Check the downloaded codebase periodically as ransomware can tamper with memory, disk storage, or chipset buses.
- Implementations that do not require backups are safer without an apikey omitting any admin access.
- The logic deletes unused items periodically for safety and privacy. It is ideal for self-healing demos.
- Make sure to limit physical access to cloud instances to protect the data. No SSH, console, extensions etc.

You can even fetch public operating system update binaries through unencrypted http.
Try something like `http://example.com/5fe8...1ec.tig`. It is secure, if you verify the hash `5fe8...1ec` downstream.
This power eliminates any man-in-the-middle attack possibilities due to the design of TLS being opaque and encrypted for the most important files.
Governments can monitor the channel without affecting the code integrity of the corporate networks.
This integrity was the power of early DOS and Windows systems that partly made Microsoft so successful.

## The power

There are some ways developers can extend it to be powerful.

- Backup tools can directly work with the uploaded data easily.
- The client can address the data file any time with its SHA256 hash.
- The client can XOR split the stream to two different cloud providers lowering privacy risks.
- The client can do striping to two or more different datacenters doubling bandwidth.
- File cleanup delay can be adjusted to act like a cache or the legal backup.
- We tested 100 ms nearby and 500 ms latency to continental cloud regions.
- File hashes act like page and segment addresses of Intel and AMD process pages.
- Such an arrangement helps to create distributed memory based processes.
- A simple html [page](https://gitlab.com/eper.io/sat) can build a distributed process leveraging server memory.
- A process with distributed memory can span across servers supporting serverless and GenAI batch workloads at scale.
- Second, minute, day, and week retention of remote memory are able to run workloads like a GC heap.
- The setup can work as an in-memory distributed process with optional disk swap.
- Memory mapped, and swap volumes can speed up frequently accessed files but provide more space.
- An off the shelf wrapper can customize authorization and security.
- If you need to scale reading back the same data, we suggest to use a Kubernetes ingress of 2-5 nodes.
- You can use scaling with our Mitosis algorithm, the cloud investor's and CFO's best dream.
- Handling a large bandwidth input can be solved with an iSCSI Linux cluster making it a distributed machine.
- A simple SHA256 on a file or a directory tar or zip can identify an entire version.
- We eliminate external API calls to git and a necessary download of git binaries on each container.
- There is no need of complex protocol binaries of git to check out. It is HTTP.
- tig is ideal for data streaming workloads as a middle tier.
- tig can handle streaming bottlenecks as a result being cleaned up.
- tig cannot force update a push like git. Any deletion propagates over time giving a chance to restore.
- See [example](documentation/commit.sh) to see the power of a code commit generating docker script.
- The hash construct can help to remote load less frequently used libraries like DLLs on Unix/Windows.
- Hash addressing makes it safer to download and run scripts like get.docker.com.
- You can verify anytime, what ran by hashing the entire launch payload.
- Distributed databases are easy to merge with hash granularity similar to commit sizes.
- It is super simple to use the same backend for critically distinct workloads.
- Still, separate workloads can share data with the same hash to save on memory space.
- Repetitive patterns can be compressed at the level of the block file system.

## Examples

```
echo test > /tmp/test
echo abc > /tmp/apikey
curl 'http://127.0.0.1:7777/?apikey=abc'
curl -X PUT 'http://127.0.0.1:7777/?apikey=abc' -T /tmp/test
curl -X POST 'http://127.0.0.1:7777/?apikey=abc' -T /tmp/test
curl 'http://127.0.0.1:7777?apikey=abc'
curl 'http://127.0.0.1:7777/f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2.tig'
cat /tmp/test | sha256sum | head -c 64
printf "http://127.0.0.1:7777/`cat /tmp/test | sha256sum | head -c 64`.tig"
# Errors, formatting, and random content
curl 'http://127.0.0.1:7777/randomfileunauthorized'
uuidgen | sha256sum | head -c 64 | curl --data-binary @- -X POST 'http://127.0.0.1:7777?format=http://127.0.0.1:7777*'
curl 'http://127.0.0.1:7777?apikey=abc&format=http://127.0.0.1:7777*'
# Commit the current directory
tar --exclude .git -c . | curl --data-binary @- -X POST 'http://127.0.0.1:7777/?apikey=abc'
zip -r -x '.*' - . | curl --data-binary @- -X POST 'http://127.0.0.1:7777/?apikey=abc'
# Do a full backup of the remote repository locally
curl -s 'http://127.0.0.1:7777?apikey=abc' | xargs -I {} curl -s 127.0.0.1:7777{} --output .{}
```

The main design decision is to let the client deal with ordering and tagging.
This makes the server side and the protocol simple.
Each repository can contain files from multiple projects.
Any repeated patterns can be compressed at the file system level.

## Key Value Store

Using tig as a traditional key value store is a minor feature. The reason is that hashes ensure that the data is cryptographically secure. Once we store by the hash of the key instead of the hash of the value, the value can change.

- Use a burst of hashed segments to represent large files or database snapshots with hashes as pointers.
- Change just the index nodes on updates.
- Only the root snapshot key requires a value stored by a key.
- We just `PUT` the data, and refer to it later with the hash of the value in the non-key-value case.
- We use the hash of the key in case of the key-value case.
- We specify the key with its SHA256 hash in the path.
- We `HTTP PUT` to this hashed key path with the data as body to store a key value pair.
- The presence of the path at `HTTP PUT` indicates that this is a key value pair, not raw data.
- The hash of a key will collide with any other storage of that pattern.
- Use the hash of the hash of a key to resolve this conflict of patterns.
- If a data file has been stored by its hash, we do not allow it to be overwritten as a key value pair.
- The key hash returned on success can be used later to update the key value pair as many times as desired.
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

We rely on file system level synchronization such as O_EXCL. We do not use processor test and set (TAS) or (XCHG) considered expensive for memory buses on shared cores.
Setting a variable only, if it was not set is good enough for synchronization w/ retry for most use cases such as creating a mutex/semaphore for lambda function runs.

The following call will only return the path, if we successfully set the specified file used as an exclusive slot. It will return empty, if it is used.

```
echo 123 | curl -X 'PUT' --data-binary @- 'http://127.0.0.1/7574284e16a554088122dcd49e69f96061965d7c599f834393b563fb31854c7f.tig?setifnot=1'
```

The following call will append to the file using file system level synchronization just like `>>log.txt`. This helps with logs and traces. Use a random hash path for proper behavior.

```
echo We added one more file. | curl -X 'PUT' --data-binary @- 'http://127.0.0.1/7574284e16a554088122dcd49e69f96061965d7c599f834393b563fb31854c7f.tig?append=1'
```

## Storage directory suggestions:

`/data` is the default location that can be created before startup.

`/tmp` and any `tmpfs` : It cleans up fast, it is sometimes low latency memory based storage.

`/usr/lib` : It is a good choice for executable modules. It is persistent.

`/var/log` : Choose this for persistent data. It is persistent across reboots.

`/opt/` : Use this for entire solutions. It is persistent.

`~/` : Use, if you run outside a container without privileges, but you need persistence across reboot.

It is a good idea to perform delayed delete on files setting the cleanup period.

Clients can keep resubmitting or accessing them making the system more resilient.

Updates and queries reset the timer. The timer restarts on existing data when we restart the container.

Such systems comply easier with privacy regulations. It is just a temporary cache not a root storage.

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

- We forward requests to all active pods.

## Benchmark

We achieved the minimum practical latency of sustained 13 ms on an Apple Mac Studio. This is not bad for a golang codebase.

Better performance could be achieved by C or C++ LLM transformations, better dos handling and direct UDP implementation.

```
while true; do uuidgen | time curl http://127.0.0.1:7777`time curl -X 'PUT' --data-binary @- 'http://127.0.0.1:7777'`; done
```

There are a few hints how to optimize for the best performance.

Use a memory mapped drive as the data directory. Ideally this is tmpfs.

Tmpfs and ext4 both have limitations of minimum file size of 4K on Intel and 8K on ARM. Try to use bigger buffers as a result.

If you have to use very small data bits, then it is better to keep updating the same file using a key value pair instead of hashed storage.

10 minute is a good retention period for demos, 1 GBps is a common cloud bandwidth. These were used to set the default file size.

The benchmarks are limited due to the need to read the entire stream to maintain hashes and find the right location.
This helps on the other hand with a robust security, especially for sensitive code and binaries.

## Strategy

- Scheduling cleanups at startup covers migrations due to hardware upgrades.

- Do not rely on cleanup to cover any restart issues.

- Crashes or hangs should be fixed instead.

- We keep the code less than a few hundred lines to be easy to audit.

- Cluster forwarding would normally use a UDP broadcast or multicast on regular nodes.

- Since we may use K8S we opt for querying a DNS address specified by a headless service.

- The HTTP forwarding logic makes the solution very flexible.

- Fully utilizing standalone GPU, memory, and disk clusters is an opportunity.

- Clusters can scale using pod termination signals, an additional API, or timeout.

- We decided to implement cluster balancing with a timeout to offload & terminate.

- Terminating with a timeout is very deterministic and secure way to offload and scale in & out.

- Use a cluster of two nodes or more to implement cluster balancing.

- The ever replacing dynamism of pods with lifetime makes the solution flexible and scalable.

- The latest codebase is always at [https://gitlab.com/eper.io/tig](https://gitlab.com/eper.io/tig) to support multiple providers increasing the negotiation power of the community.

- There is a mirror at [https://github.com/eper-io/tig](https://github.com/eper-io/tig)

## Kubernetes

You can run tig as a cluster deployment with multiple pods on Kubernetes.

Here is an example yaml file that we tested with Amazon EKS.

Generate a code file running tig already on example.com. Place `certificate.crt`, `ba_bundle.crt`, `private.key` into `./.implementation/example.com`

You can either use Letsencrypt or zerossl as described above.

```bash
IMPLEMENTATION=./.implementation/example.com DATAGET=https://example.com DATASET=https://example.com ./documentation/tig.sh
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

## TODO

- tig was actually an idea too quick. It is not really a `git` clone anymore. We could rename this to `storage` or even better `route` that reflects the behavior.
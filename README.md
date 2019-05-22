# ssh-proxy

Most simples Secure Shell proxy to control access of your engineering/support team(s) to private servers.


## Inspiration

This tool is for a company that provide support to clients, small engineering teams or start-ups. Anyone who needs centralized, secure and simples access governance to private server. It offers an alternative solution to *authorized_keys*.

**Why not authorized_keys on server?**

Imagine that you need to ask for root access on client's server. If you put public keys of all your engineers on client's server, then you need to maintain list of client's servers to delete these keys and you need to disclose list of your people.

All this is a bad idea, especially when you will corrupt authorized_keys on server by running your automation tool and client's simultaneously.

This tool will allow to put only one public key on server and maintain access through this key.

Secondly, it solves a problem of SSH access provision in the ad-hoc cloud environment, where new servers automatically comes and goes. 

As **benefits**, you gets

1. No LDAP, Kerberos or any other nightmare technologies
2. No need to share private key with all your team including fired people
3. All actions are logged so that you will be able to find, who have dropped production database

Please be aware that solution is still **under development**.


## Key features

* Secure shell proxy.
* Secure port forwarding via stdio.
* Of-the-shelf deployment to docker-based environments. 


## Getting started

SSH proxy is a daemon that helps you to control access of your support team to customers servers with following workflow:

1. You create your team key pair
2. Give public key to all customers
3. Store private key on a private server that runs a proxy. The access to this server has to be limited to yourself
4. Take public key from your support personnel
5. Upload them on that proxy server
6. Now your support stuff can login to customer server unless you revoke this access

Use the proxy to control access of your engineering team to cloud servers with similar workflow

1. Use the console to generate key pair(s) for your environment.
2. Upload the private key to a ssh-proxy server.
3. Take public key from your engineers (e.g. github identity)
4. Upload public keys on that proxy server.
5. Now your support stuff can login to cloud servers unless you revoke this access

### Running the proxy

The easiest way to run Secure Shell proxy is Docker containers, there are available pre-build images at `flussonic/ssh-proxy`. Alternatively, you can use [Erlang escript](http://erlang.org/doc/man/escript.html) to spawn a daemon but it requires an installation of [Erlang OTP/19 or later release](http://www.erlang.org).

```bash
docker run -it --rm --name ssh-proxy \
    -p ${CONFIG_SSH_PORT}:2022 \
    -v ${CONFIG_SSH_AUTH}:/opt/data/auth \
    -v ${CONFIG_SSH_USERS}:/opt/data/users \
    flussonic/ssh-proxy
```

Use environment variables or other means to configure the proxy container

```bash
## defines a port used by proxy
export CONFIG_SSH_PORT=2022

## location of server's private key
export CONFIG_SSH_AUTH=/tmp/ssh/auth

## location of user's publick key. Only these user will be able to build a tunnel
export CONFIG_SSH_USERS=/tmp/ssh/users
```

### Configure a private key

Upload a team private key (the key that provisions access to all private servers) `id_rsa` to `${CONFIG_SSH_AUTH}` folder on ssh-proxy server.


### Add/revoke users access

Upload users public key to `${CONFIG_SSH_USERS}` folder on ssh-proxy server. Name the file after the users name. User's access is revoked if you delete this key from the proxy.


### Establish Secure Shell session

Your team needs to update `~/.ssh/config` file with details of ssh proxy

```
Host ssh-proxy
   HostName 127.0.0.1
   Port 2022
   User my-user-name
   IdentityFile ~/.ssh/my-public-key
```

Please note that proxy has a special syntax to identify private servers. Username, host and ports have to be specified like `user/host/port`.

```bash
ssh user/private-host@ssh-proxy
```


### Port forwarding

[Erlang SSH subsystem](http://erlang.org/pipermail/erlang-questions/2018-January/094706.html) do not supports a standard ssh port forwarding. The proxy daemon implements a port forwarding using standard I/O. Using a special syntax:

```bash
ssh user/private-host~forward-host/port@ssh-proxy
```

Once SSH connection is established, any `stdin` is delivered to `forward-host/port` and its response available at `stdout` of your local ssh process. A following scripts helps you to attach ssh stdio to any local port.

```bash
mkfifo pipe
while [ 1 ]
do

nc -l 8080 < pipe | ssh -T user/private-host~forward-host/port@ssh-proxy | tee pipe > /dev/null

done
```

## How To Contribute

The project accepts contributions via GitHub pull requests.

1. Fork it
2. Create your feature branch `git checkout -b my-new-feature`
3. Commit your changes `git commit -am 'Added some feature'`
4. Push to the branch `git push origin my-new-feature`
5. Create new Pull Request

The proxy development requires [Erlang OTP/19 or later release](http://www.erlang.org).

Use the following command to run the proxy locally for RnD purposes

```bash
escript ssh-proxy.erl \
   -p 2022 \
   -i /tmp/ssh/auth \
   -u /tmp/ssh/users \
   -t /tmp/ssh/server
```


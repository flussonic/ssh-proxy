# ssh-proxy

Most simples Secure Shell proxy to control access of your engineering/support team(s) to private in-house network resources or customer premises.


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

* Secure Shell proxy
* Secure port forwarding using stdio.
* Compatible with docker


## Getting started

The proxy is shipped using [Erlang escript](escript) and pre-build images for Docker. Easiest way to run a standalone instance is with the Docker container.

```
docker run -it --rm --name ssh-proxy \
    -p ${PORT}:2022 \
    -v ${PATH_TO_AUTH_DATA}:/opt/data/auth \
    -v ${PATH_TO_USERS_DATA}:/opt/data/users \
    flussonic/ssh-proxy
```

    # server path must contain sshd host key named "ssh_host_rsa_key"
    -v PATH_TO_USERS_DATA:/opt/data/server \
    flussonic/ssh-proxy


### Workflow

SSH proxy is a daemon that helps you to control access of your support team to customers servers with following workflow:

1. You create your team key pair
2. Give public key to all customers
3. Store private key on a private server where only you can login
4. Take public key from your support guy
5. Upload it on that private server
6. Now your support stuff can login to customer server unless you revoke this access




## How To Contribute



# How to use?

You can run `ssh-proxy` with lightweight docker image.

```
docker run -d --rm --name ssh-proxy \
    -p PORT:2202 \
    -v PATH_TO_AUTH_DATA:/opt/data/auth \
    -v PATH_TO_USERS_DATA:/opt/data/users \
    # server path must contain sshd host key named "ssh_host_rsa_key"
    -v PATH_TO_USERS_DATA:/opt/data/server \
    flussonic/ssh-proxy
```




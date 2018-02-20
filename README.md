# ssh-proxy

SSH proxy is a daemon that helps you to control access of your support team to customers servers with following workflow:

1. You create your team key pair
2. Give public key to all customers
3. Store private key on a private server where only you can login
4. Take public key from your support guy
5. Upload it on that private server
6. Now your support stuff can login to customer server unless you revoke this access

# Why not authorized_keys on server?

This tool is for a company that provide support to clients.
Imagine that you need to ask for root access on client's server. If you put public keys of all your engineers on client's server, then you need to maintain list of client's servers to delete these keys and you need to disclose list of your people.

All this is a bad idea, especially when you will corrupt authorized_keys on server by running your automation tool and client's simultaneously.

This tool will allow to put only one public key on server and maintain access through this key.

# Pro

1. No LDAP, Kerberos or any other nightmare technologies
2. No need to share private key with all your team including fired people
3. All actions are logged so that you will be able to find, who have dropped production database

# Cons

Not finished yet.

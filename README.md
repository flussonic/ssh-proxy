# ssh-proxy

SSH proxy is a daemon that helps you to control access of your support team to customers servers with following workflow:

1. You create your team key pair
2. Give public key to all customers
3. Store private key on a private server where only you can login
4. Take public key from your support guy
5. Upload it on that private server
6. Now your support stuff can login to customer server unless you revoke this access

# Pro

1. No LDAP, Kerberos or any other nightmare technologies
2. No need to share private key with all your team including fired people
3. All actions are logged so that you will be able to find, who have dropped production database

# Cons

Not written yet.

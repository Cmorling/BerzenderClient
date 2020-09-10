# Berzender Client 2020

## Description

This is a project to complete the programing courses in my high school. This is the client of Berzender.

Welcome to berzender. Here you can create an account and send a message to any user on the network, no friending required. Likewise, you are also exposed on the network and can be sent messages from any user.
Your password is hashed with SHA256 before it's sent to the server to prevent your password from being leaked in a data breach.
Messages are encrypted with RSA private and public keys, the public keys are stored on the server and are fetched anytime a user wants to send a message to you.
The private key is stored safely on your local machine.

## Requirements

### Python and Pip

- **Python3.x** ~ <https://www.python.org/downloads/>
- **Pip20.1** ~ <https://pip.pypa.io/en/stable/installing/>

### Dependencies

There is a conflict between pycrypto, crypto and pycryptodome. So make sure you have removed both of these packages before you install pycryptodome.

`# pip uninstall pycrypto crypto`
`# pip install -r requirements.txt`

## Executing

Run the client with the ip and port of the server to establish a connection, then log in with your credentials and start sending messages. You can save your credentials in `config.txt`.

usage: client.py [-h] [-i IP] [-p Port]

Berzender Client to connect to a server

optional arguments:
  -h, --help  show this help message and exit
  -i IP       Ip of Berzender server
  -p Port        Port of Berzender server

Example:
`# python3 client.py -i 127.0.0.1 -p 1337`

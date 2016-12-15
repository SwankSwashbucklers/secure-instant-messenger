# Secure Instant Messenger

An instant messenger server and client pair, with communication between server instance and client instance, and between client instances encrypted and secure.

## Getting Started

This project makes use of an unreleased build of the cryptography library.  So, to avoid configuration issues, all dependencies for the project are contained in the project's virtual environment.  To set up, first navigate to the root of the project in a shell and then use one of the following commands to activate the virtual environment:  

```sh
# for bash shells
source .venv/bin/activate

# for fish shells
. .venv/bin/activate.fish

# for csh shells
source .venv/bin/activate.csh
```

After the virtual environment is activated, the following commands are made available:

```sh
# print usage of server.py
python server.py --help

# print usage of client.py
python client.py --help

# run the server with the default options
python server.py

# run the client with the default options
python client.py

# deactivate the virtual environment
deactivate
```

## Using The Program

### Server

The server needs to be running in order for the clients to be able to login, logout, or open any new conversations with other clients.

### Client

When the client starts, you will be prompted for a username and password, in order to authenticate yourself with the server.  The server is preconfigured with three user accounts, their credentials are:

| Username | Password     |
| -------- | ------------ |
| Alice    | Whit3R@bbit  |
| Bob      | joy0painting |
| Trudy    | valkyries48  |

Once you are logged in, you may use any of the commands below to interact with the program:

```sh
# list the users that are currently logged in
list

# manually request an update for the CRL (rarely needed as the CRL is automatically updated before initializing communication with any other user)
crl

# send a message (<MESSAGE>) to the given user (<USER>)
send <USER> <MESSAGE>

# logout from the server
logout

# attempt logout and then exit the application
exit
```

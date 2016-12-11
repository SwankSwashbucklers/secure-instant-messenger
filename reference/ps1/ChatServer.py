from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from socket import socket, AF_INET, SOCK_DGRAM

### Command Line Interface #####################################################

parser = ArgumentParser(
    formatter_class=ArgumentDefaultsHelpFormatter,
    description=__doc__ )
parser.add_argument("-sp", "--port",
    type=int,
    help="the port to run the server on.")
args = parser.parse_args()


### Server Program Body ########################################################

clients = [] # list of clients
msg_tpl = lambda a, m: '<- <from {}:{}>: {}'.format(*a, m)

# create socket and bind it to the port provided
sock = socket(AF_INET, SOCK_DGRAM)
server_address = ('localhost', args.port)
sock.bind(server_address)

print('Server Initialized...')

# during server lifetime listen for incomming messages
while True:
    data, address = sock.recvfrom(4096)
    message = str(data, 'utf-8') # decode bytes-string

    # if message starts with a G, then it is a greeting
    if message[0] is 'G':
        # dont add duplicate entries
        if not address in clients:
            clients.append(address)

    # if message starts with an M, then it is a message
    if message[0] is 'M':
        message = message[1:] # remove first character of message
        for client in clients:
            outgoing_msg = msg_tpl(address, message)
            outgoing_msg = outgoing_msg.encode('utf-8') # encode message
            sock.sendto(outgoing_msg, client)

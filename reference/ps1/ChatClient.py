from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from socket import socket, AF_INET, SOCK_DGRAM
from _thread import start_new_thread
from sys import stdout

### Command Line Interface #####################################################
parser = ArgumentParser(
    formatter_class=ArgumentDefaultsHelpFormatter,
    description=__doc__ )
parser.add_argument("-sip", "--server_ip",
    type=str,
    help="the ip of the server.")
parser.add_argument("-sp", "--server_port",
    type=int,
    help="the port that the server is running on.")
args = parser.parse_args()


### Client Program Body ########################################################

# create the necessary sockets
outgoing_socket = socket(AF_INET, SOCK_DGRAM)
receiving_socket = socket(AF_INET, SOCK_DGRAM)

server_address = (args.server_ip, args.server_port)

# send GREETING
receiving_socket.sendto(b'G', server_address)

# start the thread that will listen for messages from the server
def listen_for_data():
    while True:
        data, address = receiving_socket.recvfrom(4096)
        message = str(data, 'utf-8') # decode message
        stdout.write('\033[1G') # move cursor to beginning of line
        print(message, '\n+> ', end="")

try:
    start_new_thread(listen_for_data, ())
except:
    print("Error: unable to start thread")

# print initial prompt
print('+> ', end="")

# during lifetime of the client listen for user keyboard input
while True:
    message = input('')
    message = 'M' + message # append M to mark it as a message
    message = message.encode('utf-8') # encode outgoing message

    try:
        outgoing_socket.sendto(message, server_address)
        message_sent = True
    except:
        print('Error: unable to send message')
        print('+> ', end="")

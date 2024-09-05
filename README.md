# udp-to-tcp

The purpose of the client, server, and proxy programs is to transmit data reliably from
the client to the server using UDP with IPv4 or IPv6 communication. Since there is not a
lot of noise in a local network, the proxy is configured with options to drop packets and
add delays to simulate a noisy channel. The client makes a connection with the server
by communicating through the proxy, which decides to drop, delay, or forward the
packet. Once the server’s ACK reaches back to the client, the client reads data from a
file and sends that data in packets to the server. The server responds to each packet of
data that successfully reaches it with an ACK. Essentially, the programs use a
stop-and-wait approach to reliably transfer data. When the client sends a packet, it waits
for an ACK from the server before sending more packets of data. The client will write to
the standard output when it creates the initial packet for a piece of data, retransmit a
packet when a timeout occurs, and when it receives an ACK back. The proxy will drop a
packet, drop the delay on a packet, or route it to its intended destination and prints to
the standard output what action it takes for every incoming packet. The server prints to
the standard output when it receives a packet and when it sends an ACK back to the
client. Also, the server is designed to handle only one client at a time. As in, only one
client and connect and complete and then another can connect and transmit its data.

The points below outline the initial arguments and options of the client, server, and
proxy programs.
 - Client
    - The client requires five arguments from the command line
        - <ip address>
        - <port>
        - <proxy ip address>
        - <proxy port>
        - <filepath>
 - Server
    - The server requires two arguments from the command line
        - <ip address>
        - <port>
 - Proxy
    - The proxy requires six arguments from the command line
        - <ip address>
        - <port>
        - <client ip address>
        - <client port>
        - <server ip address>
        - <server port>
    - The proxy accepts eight options from the command line
        - --cdrop <value> (client drop chance)
        - --sdrop <value> (server drop chance)
        - --cdropdelay <value> (client delay drop chance)
        - --sdropdelay <value> (server delay drop chance)
        - --cmindelay <value> (client minimum delay)
        - --cmaxdelay <value> (client maximum delay)
        - --smindelay <value> (server minimum delay)
        - --smaxdelay <value> (server maximum delay)

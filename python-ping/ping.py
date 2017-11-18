
__author__      = "Bhavin Shah"

import socket
import struct
import random
import time
import select
import six
import sys
import getopt


ICMP_ECHO_REQ = 8
ICMP_ECHO_REPLY = 0
ICMP_PROTOCOL = socket.getprotobyname('icmp')


def checksum(str):
    """
    This function finds checksum of a given input string
    :param str: input string
    :return: checksum
    """
    csum = 0
    i = 0

    while (i + 1) < len(str):
        if six.PY3:
            csum += str[i + 1] * 256 + str[i]
        else:
            csum += ord(str[i + 1]) * 256 + ord(str[i])
        csum &= 0xffffffff
        i += 2

    if i < len(str):
        if six.PY3:
            csum += ord(str[i])
        else:
            csum += str[i]
        csum &= 0xffffffff

    # add high 16 bits to low 16 bits
    csum = (csum >> 16) + (csum & 0xffff)
    # add carry
    csum += (csum >> 16)
    csum = ~csum
    csum &= 0xffff

    if sys.byteorder == 'little':
        return csum
    else:
        return socket.htons(csum)


def get_packet(pkt_id, sequence, packetsize):
    """
    This function creates a icmp packet with given packet id, sequence number and packetsize of data
    :param pkt_id: the packet identifier
    :param sequence: sequence number
    :param packetsize: size of data in packet
    :return: icmp packet
    """
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    # ctype: signed char, signed char, unsigned short, unsigned short, short
    my_checksum= 0
    header = struct.pack("bbHHh", ICMP_ECHO_REQ, ICMP_ECHO_REPLY, my_checksum, pkt_id, sequence)

    data = b''
    for i in range(0, packetsize):
        data += struct.pack("b", 8)

    my_checksum = checksum(header + data)
    header = struct.pack('bbHHh', ICMP_ECHO_REQ, ICMP_ECHO_REPLY, my_checksum, pkt_id, sequence)

    packet = header + data
    return packet


def is_valid(addr):
    """
    This function return true if the given address is valid ip address, false otherwise
    :param addr: address
    :return: boolean
    """
    parts = addr.split(".")
    if not len(parts) == 4:
        return False
    for i in parts:
        try:
            part = int(i)
        except ValueError:
            return False
        else:
            if part > 255 or part < 0:
                return False
    return True

def to_ip(addr):
    """
    This function converts a given address to ip address
    :param addr: address
    :return: ip address
    """
    if is_valid(addr):
        return addr
    return socket.gethostbyname(addr)

def print_unknown_host(e):
    print("Ping request could not find host " + str(e) + " Please check the name and try again.")


def do_ping(dest, rep, wait, timeout, packetsize):
    """
    This function pings a given target for rep number of times or indefinitely if #rep = -1
    :param dest: target
    :param rep: # times to ping
    :param wait: wait time between two pings
    :param timeout: timeout for each ping
    :param packetsize: size of data in each packet
    :return: None
    """
    try:
        dest_ip = to_ip(dest)

    except socket.gaierror as e:
        print_unknown_host(e)
        return
    else:
        print("Pinging "+str(dest)+" ["+str(dest_ip)+"] with "+str(packetsize)+" bytes of data:")

    packets_sent = 0
    packets_received = 0
    rtt = []
    times = 1
    while not rep == 0:
        delay = single_ping(dest_ip, timeout, times, wait, packetsize)
        packets_sent += 1
        if not delay == None:
            rtt.append(delay)
            packets_received += 1
        rep -= 1
    print_statistics(dest_ip, packets_sent, packets_received, rtt)


def single_ping(dest_ip, timeout, sequence, wait, packetsize, ttl=55):
    """
    This function sends a single packet to given target ip address
    :param dest_ip: target ip address
    :param timeout: timeout for each ping
    :param sequence: sequence number of packet sent
    :param wait: wait time between next ping
    :param packetsize: size of data in each packet
    :param ttl: time to live of icmp packet sent
    :return: time taken for reply
    """
    soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_PROTOCOL)
    soc.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
    pkt_id = int(timeout * 1000 * random.random()) % 65535

    time_left = timeout
    sent = soc.sendto(get_packet(pkt_id, sequence, packetsize), (dest_ip, 8080))
    time_sent = time.time()

    while time_left > 0:

        ready = select.select([soc], [], [], time_left)

        if not ready[0]:  # Timeout
            print("Request timed out.")
            return

        time_left -= (time.time() - time_sent)
        rec_packet, (rec_addr, port) = soc.recvfrom(1024)
        icmp_header = rec_packet[20:28]
        type, code, csum, p_id, sequence = struct.unpack('bbHHh', icmp_header)

        ip_header = rec_packet[:20]
        _, _, _, _, _, ttl, _, _, _, _ = struct.unpack("!BBHHHBBHII", ip_header)
        if p_id == pkt_id:
            time_taken = int((timeout - time_left) * 1000)
            print("Reply from " + str(rec_addr) + ": bytes=32 time=" + str(time_taken) + "ms TTL=" + str(ttl))
            time.sleep(wait)
            return time_taken


def print_statistics(dest_ip, sent, received, rtt):
    """
    This function prints ping statistics
    :param dest_ip: target ip address
    :param sent: packets (ECHO REQUESTS) sent to the target
    :param received: packets(ECHO REPLY) received from target
    :param rtt: round trip time
    :return: None
    """
    print("Ping statistics for " + str(dest_ip) + ":")
    lost = sent - received
    percent_loss = lost * 25
    print("\tPackets: Sent = "+str(sent)+", Received = "+str(received)+", "\
            + "Lost = "+str(lost)+" ("+str(percent_loss)+"% loss),")

    if len(rtt) > 0:
        print("Approximate round trip times in milli-seconds:")
        rtt_min = min(rtt)
        rtt_max = max(rtt)
        rtt_avg = sum(rtt) / float(len(rtt))
        print("\tMinimum = "+str(rtt_min)+"ms, Maximum = "+str(rtt_max)+"ms, Average = "+str(rtt_avg)+"ms")


def usage():
    """
    This funciton prints ping usage
    :return: None
    """
    print("")
    print("Usage: ping [-t timeout] [-s packetsize] [-c count] [-i wait] target_name")
    print("Options:")
    print("    -t             timeout, in seconds, before each ping exits.")
    print("    -c count       Number of echo requests to send.")
    print("    -s packetsize  Send data size.")
    print("    -i wait        wait seconds between sending each packet.")

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'c:i:t:s:h', '--help')
    except getopt.GetoptError:
        print("Bad options.")
        usage()
        sys.exit(0)

    no_of_probes = -1
    wait = 1
    timeout = 1
    packetsize = 32

    try:
        for opt, arg in opts:
            if opt in ('-h', '--help'):
                usage()
                sys.exit(0)
            elif opt == '-c':
                no_of_probes = int(arg)
            elif opt == '-i':
                wait = int(arg)
            elif opt == '-t':
                timeout = int(arg)
            elif opt == '-s':
                packetsize = int(arg)

    except ValueError:
        print("Error parsing options.")
        usage()

    else:
        if len(args) <= 0:
            print("A target name or address must be specified.")
            usage()
        else:
            do_ping(args[0], no_of_probes, wait, timeout, packetsize)

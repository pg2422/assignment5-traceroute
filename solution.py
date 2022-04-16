from socket import *
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 1
# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise

def checksum(string):
# In this function we make the checksum of our packet
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def build_packet():
    myChecksum = 0
    ID = os.getpid() & 0xFFFF
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header

    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)

    packet = header + data
    return packet

def get_route(hostname):
    timeLeft = TIMEOUT
    tracelist1 = [] #This is your list to use when iterating through each trace 
    tracelist2 = [] #This is your list to contain all traces
    
    tracelist = []
    reached_dest = False
    for ttl in range(1,MAX_HOPS):
        result_times = []
        resolved_hostname = "Request timed out."
        for tries in range(TRIES):
            destAddr = gethostbyname(hostname)

            mySocket = socket(AF_INET, SOCK_RAW, getprotobyname("icmp"))

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t= time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if whatReady[0] == []: # Timeout
                    result_times.append("*")
                    # tracelist2.append([str(ttl), "*", "Request timed out."])
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    result_times.append("*")
                    # tracelist2.append([str(ttl), "*", "Request timed out."])
            except timeout:
                continue

            else:
                #Fetch the icmp type from the IP packet
                types = struct.unpack("b", recvPacket[20:21])[0]
                
                try: 
                    #try to fetch the hostname
                    resolved_hostname = gethostbyaddr(addr[0])[0]
                except herror:   
                    #if the host does not provide a hostname
                    resolved_hostname = addr[0]

                if types == 11:
                    bytes = struct.calcsize("d")
                    if (len(recvPacket) >= 0x38 + bytes):
                      timeSent = struct.unpack("d", recvPacket[0x38:0x38 + bytes])[0]
                      pingTime = timeReceived - timeSent
                      result_times.append(f"{pingTime*1000:.0f}ms")
                    else:
                      result_times.append("*")
                elif types == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    result_times.append("*")
                elif types == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    pingTime = timeReceived - timeSent
                    result_times.append(f"{pingTime*1000:.0f}ms")
                    reached_dest = True
                else:
                    result_times.append("*")
                # break
            finally:
                mySocket.close()
                
        cur_trace = [str(ttl)]
        cur_trace.extend(result_times)
        cur_trace.append(resolved_hostname)
        
        tracelist.append(cur_trace)
        
        if (reached_dest):
          break
                
    return tracelist

if __name__ == '__main__':
    get_route("google.co.il")
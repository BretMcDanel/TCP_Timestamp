#!/usr/bin/env python3
'''
This is a rewrite of a program I originally did in C in 2011.  It is not well tested.
This program shows how it is possible to recover TCP timestamps from a connection.
Originally the program would reveal the uptime of a system, however there are
side channel attacks and other information leakage applications available.
'''

from scapy.all import *
import argparse
import time

def getTS(host, port):
    '''
    This will only do a SYN and not the full 3-way handshake.  As noted in the original paper Win2k did not send a TS
    until data was sent to it.  I no longer have a Win2k box to test against so I dont do that anymore.

    If you need to actually send data you will have to do the 3-way handshake yourself (lots of examples exist) or you will
    have to run the sniffer in a separate thread/process
    '''
    packet = sr1(IP(dst=host)/TCP(sport=5150, dport=port, flags="S", options=[('Timestamp', (1337,0))], seq=100), verbose=0)
    for opt, val in packet[TCP].options:
        if opt == 'Timestamp':
            TSval, TSecr = val
            return TSval
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Timestamp collector.")
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    parser.add_argument("-s", "--server", help="Server name to connect to", required=True)
    parser.add_argument("-p", "--port", help="Port to connect to", required=True)
    args = parser.parse_args()
    
    
    TSval1 = getTS(args.server, int(args.port))
    # Wait 1 second to get the tick interval
    time.sleep(1)
    TSval2 = getTS(args.server, int(args.port))

    tickrate = TSval2 - TSval1
    if tickrate:
        if(tickrate < 1300 and tickrate > 700):
            tickrate=1000
        elif(tickrate < 130 and tickrate > 70):
            tickrate=100
        elif(tickrate < 30 and tickrate > 7):
            tickrate=10
        elif(tickrate < 4 and tickrate > 1):
            tickrate=2
        else:
            print("Unknown tickrate - uptime may be incorrect")
                
        day=int((TSval2/tickrate)/86400);
        sec=int((TSval2/tickrate)%86400);
        hour=int(sec/3600);
        sec=int(sec%3600);
        m=int(sec/60);
        sec=int(sec%60);
        
        print(f"{args.server} (Tickrate {tickrate}/sec) Uptime: {day} days, {hour:02d}:{m:02d}:{sec:02d}")
    else:
        print("The remote system does not appear to support TCP Timestamping")

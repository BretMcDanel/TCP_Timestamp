#!/usr/bin/env python3

from scapy.all import *
import argparse
import _thread
import time
import select
import os

def sniff_packets(host, port, iface=None):
    '''Sets up the packet sniffer'''
    try:    
        if iface:
            #sniff(filter="port "+str(port), prn=process_packet, iface=iface, store=False)
            sniff(filter="((tcp[tcpflags] & tcp-ack) != 0) and host " + host + " and port " + port, prn=process_packet, iface=iface, store=False)
        else:
            sniff(filter="host "+host+" and port "+port, prn=process_packet, store=False)
    except:
        print("Unable to sniff packets, do you have suitable permission")
        os._exit(1)

def process_packet(packet):
    '''Processes the packets, updating the timestamp as needed'''
    global TSval
    
    if TCP in packet:
        for opt, val in packet[TCP].options:
            if opt == 'Timestamp':
                TSval, TSecr = val

def getTS(host, port):
    '''Connects to a host on a given port
       Will send data if required
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, int(port)))
    s.setblocking(0)
    ready = select.select([s],[], [], 1)
    if ready[0]:
        foo = s.recv(1024)
        if TSval == 0:
            s.send(bytes("Spooky message","utf-8"))
            ready = select.select([s], [], [], 1)
            if ready[0]:
                foo = s.recv(1024)
        
    s.shutdown(socket.SHUT_RDWR)
    s.close()
    return TSval

if __name__ == "__main__":
    TSval = 0

    parser = argparse.ArgumentParser(description="Timestamp collector.")
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    parser.add_argument("-s", "--server", help="Server name to connect to", required=True)
    parser.add_argument("-p", "--port", help="Port to connect to", required=True)
    args = parser.parse_args()
    
    
    try:
        _thread.start_new_thread(sniff_packets, (args.server, args.port, args.iface))
        time.sleep(1)
        TSval1 = getTS(args.server, args.port)
        time.sleep(1)
        TSval2 = getTS(args.server, args.port)

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
            
    except:
        print("Error: unable to start thread")


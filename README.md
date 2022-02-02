# Introduction
On March 11, 2001 I wrote a paper titled "TCP Timestamping - Obtaining System Uptime Remotely" and submitted it to the BugTraq mailing list.  This paper is included below.

At the time the nexus between system uptime and the TCP timestamp value was not widely known information.  Nmap had only added this feature 2 days before I posted my paper.  This work has also been cited by others, in fact it is probably my most cited paper.  

# The Update to Python
It is still relevant information so I thought I might revisit this and update it to use Python3 instead of C and a kernel change.  The new version uses Scapy to send a SYN packet and get the timestamp back.  If you need to send data (eg a side channel attack) you will have to implement the 3-way handshake yourself or run the sniffing component in a different thread.  Plenty of examples exist on how to do that.

This is more than just fingerprinting a system.  Side channel attacks exist when a process will return faster if the user does not exist vs it exists but the password is invalid (or if a MAC terminates on the first incorrect value).  There are many other ways to use this information.

# Cites
Got others?  Lemme know!  Even though the original paper was base research, I am still pleased that it has been cited for over **20 years** and furthered the work of others in some small way.

* [Remote Timing Techniques over TCP/IP](https://static.lwn.net/2002/0425/a/lacy.php3) - Mauro Lacy - Bugtraq April 18, 2002
* [Passive Network Discovery for Real Time Situation Awareness](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.65.3549&rep=rep1&type=pdf) Annie De Montigny-Leboeuf, Frédéric Massicotte - Communication Research Centre Canada - Presented at RTO IST Symposium on “Adaptive Defence in Unclassified Networks” April 19-20, 2004
* [TCP Timestamp To count Hosts behind NAT](http://phrack.org/issues/63/3.html) - Elie aka Lupin - Phrack issue 63 January 8, 2005
* [A Multi-Packet Signature Approach to Passive Operating System Detection](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.962.1856&rep=rep1&type=pdf)  - Defence R&D Canada - Ottawa - TECHNICAL MEMORANDUM January 2005
* [TCP timestamp & advanced fingerprinting](https://seclists.org/bugtraq/2005/Mar/460) - Clad Strife LSE - Epita/Epitech System Laboratory - Bugtraq March 25, 2005
* [Remote physical device fingerprinting](https://homes.cs.washington.edu/~yoshi/papers/PDF/KoBrCl2005PDF-Extended-lowres.pdf) Tadayoshi Kohno; Andre Broido; K.C. Claffy - IEEE Symposium on Security and Privacy 2005, IEEE Computer Society Press, May 2005 and IEEE Transactions on Dependable and Secure Computing, 2(2), 2005.
* [Time has something to tell us about Network Address Translation](https://elie.net/static/files/time-has-something-to-tell-us-about-network-address-translation/time-has-something-to-tell-us-about-network-address-translation-paper.pdf) - Elie Bursztein - Unknown date (post 2006 due to bibliography)
* [COMPUTER IDENTIFICATION USING TIME INFORMATION](https://www.vut.cz/www_base/zav_prace_soubor_verejne.php?file_id=118433) - AUTOR PRA´ CE - Masters Thesis BRNO UNIVERSITY OF TECHNOLOGY 2012
* [IP agnostic real-time traffic filtering and host identification using TCP timestamps](https://ieeexplore.ieee.org/document/6761302) Georg Wicherski; Florian Weingarten; Ulrike Meyer - 38th Annual IEEE Conference on Local Computer Networks October 21-24 2013
* [(Still) Exploiting TCP Timestamps](https://hackinparis.com/data/slides/2015/veit_hailperin_still_exploiting_tcp_timestamps.pdf) - Veit N. Hailperin - Hack In Paris June 2015
* [Leveraging Internet Background Radiation for Opportunistic Network Analysis](http://conferences2.sigcomm.org/imc/2015/papers/p423.pdf) Karyn Benson et al - IMC’15, October 28–30, 2015
* [Leveraging Internet Background Radiation for Opportunistic Network Analysis](https://escholarship.org/content/qt0561p7mq/qt0561p7mq_noSplash_87061a321d1639927c030e11de9ff8b1.pdf?t=oda9n8) Karyn Benson - Doctoral Dissertation 2016
* [On the Generation of Transient Numeric Identifiers](https://datatracker.ietf.org/doc/html/draft-irtf-pearg-numeric-ids-generation-06) - F. Gont - IETF January 13, 2021



# Link to my original mailing list submission
https://seclists.org/bugtraq/2001/Mar/182


# Original Submission
## TCP Timestamping - Obtaining System Uptime Remotely
### By Bret McDanel bret () rehost com
### March 11, 2001


TCP Timestamping can be used to retrieve information about your system that you may not wish to be public.  I started investigating this after some discussion of NetCraft's (http://www.netcraft.com/) server uptime stats, and their reliability.  Ant Mitchell was very polite in telling me NetCraft would not disclose how they obtain these figures, only that he feels they are reliable.  So I started looking into how they could get this information. What I discovered was TCP Timestamping is equal to the uptime (after a fashion) of many systems, and as such can give you extra information about the running system.


What is Timestamping?  How can it be used to gain information about a running system?  Timestamping is a TCP option, which may be set, and if set takes 12 bytes in the header (for each packet) in addition to the 20 bytes a TCP header normally takes.  This is exclusive of any other options.  What good is this overhead?  According to RFC1323:

    "The timestamps are used for two distinct mechanisms: RTTM (Round Trip
     Time Measurement) and PAWS (Protect Against Wrapped Sequences).".

I suggest that anyone interested in TCP Timestamps read RFC1323 (these are not the IP timestamping options). The fact that timestamping exists isn't anything special in itself, but how the value is populated and how the value is set is somewhat interesting.

    4.4BSD increments the timestamp clock once every 500ms and this
    timestamp clock is reset to 0 on a reboot  -- TCP/IP ILLUS v1, p349


    The timestamp value to be sent in TSval is to be obtained from a
    (virtual) clock that we call the "timestamp clock".  Its values
    must be at least approximately proportional to real time, in order
    to measure actual RTT.  -- RFC1323 May 1992

Note that the RFC does not dictate that the timestamp clock be tied to system uptime, so any system that doesn't conform to this is perfectly valid (ie Windows 2000).  Additionally the rate at which each system increments the clock need not be disclosed either, as the timestamp value is only echoed back to the sender for the sender to process.

This means that in 4.4BSD we can use this number to directly tell the time that a system has been up.  All we have to do is make a connection and record the received timestamp.  Not everyone implements timestamping this way however.  This yields various results on different operating systems.  Linux for instance increments every 1 ms, Cisco IOS increments every .1 ms.  Windows 95/98/NT4 do not support Timestamping (although rumor has it that there is a patch to enable RFC1323 functionality on 95/98/NT4) Win2k does, but this value does not appear to be directly related to uptime. This means that in order to tell the uptime we need to know what OS we are looking at, or at the very least make multiple connections and try to guess what the increment is based on elapsed time vs increment.

There are some limitations to using this method for recording uptime. Certain systems have a maximum limit on how long their 'uptime' can be. The timestamp is a 32 bit number (signed).  As such it will overflow into the sign bit after 2147483647  ticks.  Based on the number of ticks per second, you can easily determine when this will roll over.

(leap year included)
```
OS                      Ticks/sec       Rollover time
4.4BSD                     2            34 years,   8 days, 17:27:27
Solaris 2                 10             6 years, 293 days, 22:53:00
Linux 2.2+               100                      248 days, 13:13:56
Cisco IOS               1000                       24 days, 20:31:23
```

One can also map out the number of systems in a load balanced environment by connecting repeatedly to the group of machines, and inspecting the Timestamps.  For each different time you have a different machine.


RFC1323 talks about the frequency the 'timestamp clock' should be updated

         The receiver algorithm does place some requirements on the
         frequency of the timestamp clock.

         (a)  The timestamp clock must not be "too slow".

              It must tick at least once for each 2**31 bytes sent.  In
              fact, in order to be useful to the sender for round trip
              timing, the clock should tick at least once per window's
              worth of data, and even with the RFC-1072 window
              extension, 2**31 bytes must be at least two windows.

              To make this more quantitative, any clock faster than 1
              tick/sec will reject old duplicate segments for link
              speeds of ~8 Gbps.  A 1ms timestamp clock will work at
              link speeds up to 8 Tbps (8*10**12) bps!

         (b)  The timestamp clock must not be "too fast".

              Its recycling time must be greater than MSL seconds.
              Since the clock (timestamp) is 32 bits and the worst-case
              MSL is 255 seconds, the maximum acceptable clock frequency
              is one tick every 59 ns.

              However, it is desirable to establish a much longer
              recycle period, in order to handle outdated timestamps on
              idle connections (see Section 4.2.3), and to relax the MSL
              requirement for preventing sequence number wrap-around.
              With a 1 ms timestamp clock, the 32-bit timestamp will
              wrap its sign bit in 24.8 days.  Thus, it will reject old
              duplicates on the same connection if MSL is 24.8 days or
              less.  This appears to be a very safe figure; an MSL of
              24.8 days or longer can probably be assumed by the gateway
              system without requiring precise MSL enforcement by the
              TTL value in the IP layer.

         Based upon these considerations, we choose a timestamp clock
         frequency in the range 1 ms to 1 sec per tick.  This range also
         matches the requirements of the RTTM mechanism, which does not
         need much more resolution than the granularity of the
         retransmit timer, e.g., tens or hundreds of milliseconds.

As you can see all of these systems are within the RFC in their timings, however varied.


It has come to my attention that nmap 2.54beta20 released March 09, 2001 included support for detecting (multiple pass, guess at tick rate) uptimes.


If you want to quickly get the Timestamp value, you can fire up tcpdump, and watch for it.  Here is an example of what you may see and how to interpret the data:

```
myhost.12345 > theirhost.22: . 1:1(0) ack 1 win 5840
                               <nop,nop,timestamp 6426701 865450440> (DF)
```

The timestamps are located near the end of the line, where the TCP Options are printed.  The first timestamp is sent by 'myhost', the second is what 'theirhost' last sent us (we are expected to return that to them).  The numbers are the number of ticks that have accumulated in the 'timestamp clock' and if the OS supports it, can reveal an uptime.



I have included below information obtained by myself and several people running various OSs that let me scan them and compare the actual uptime vs the timestamp returned.  I do not have access to all systems to test, however I tried to include as much vendor information on RFC1323 compliance as reasonably possible.

If you are considering disabling timestamping on your system please read RFC1323 for more information (especially if you are on a fast network).

Windows

        Win2k sends the timestamp after the syn/ack handshake is complete
        (sends 0 TS during the 3-way handshake)
        95/98   does not support TS
        NT 3.5/4 does not support TS
        2000 increment every 100ms initial number random

Linux

        Sends TS on first packet replied to - default always get TS
        To disable echo 0 >/proc/sys/net/ipv4/tcp_timestamps
        To enable echo 1 >/proc/sys/net/ipv4/tcp_timestamps
        Increments 100 ticks/sec
        2.0.x does not support TCP Timestamps
        2.1.90+ Supports Timestamps
        2.2.x Supports Timestamps
        2.4.x Supports Timestamps

4.4BSD - OpenBSD BSDi BSD/OS (2.1 & 3.0) FreeBSD (2.1.5)

        To enable/disable sysctl -w TCPCTL_DO_RFC1323={true,false}
        Or sysctl -w net.inet.tcp.rfc1323={true,false}
        4.4BSD spec is applied, 2 ticks/sec

MacOS (Open Transport)

        Supports Timestamps

Novell Netware

        5 Does not support Timestamps

IRIX

        5.3+ Support Timestamps
        5.3-6.1
          /var/sysgen/master.d/bsd contains the kernel variables
          after editing you must use /etc/autoconfig and reboot (WTF!)
        6.5 edit /var/sysgen/mtune/bsd or use systune (like BSDs
        sysctl) tickrate 2/sec

HPUX

        9.x No (9.05 and 9.07 have patches to support Timestamps)
        To enable you must poke the kernel variable tcp_dont_tsecho to 0

        10.00,01,10,20,30 Support Timestamps
        
        11 Enabled by default

AIX

        3.2 & 4.1 Support Timestamps
        Tunable via the 'no' command

SunOS

        4.1.4 No (May be purchased as a Sun Consulting Special)

Solaris

        To Enable
        2.5 No (May be purchased as a Sun Consulting Special)
        2.6 may be uptime but rolls over quickly, increments 1000 ticks/second
        2.7 tickrate 100/sec (its not exactly uptime there was a 5 minute
                skew on a 112 day uptime)
        8 it is uptime, 100 ticks/second
        to enable ndd /dev/tcp tcp_tstamp_always 1
        If the parameter is set (non-zero), then the TCP timestamp option will
        always be negotiated during connection initiation. The scale option will
        always be used if the remote system sent a timestamp option during
        connection initiation. To use the timestamp, both hosts have to support
        RFC 1323.


ios (cisco)

        By default disabled To change   [no] ip tcp timestamp
        I tested only against a Cisco 2524 running 12.0(9)
        cisco 2524 (68030) processor (revision J) with 14336K/2048K bytes of memory.
        Updates 1000 ticks/sec resets to 0 at boot

comos (livingston/lucent portmasters)

        Do not support TS

Netopia

        Do not support TS

ConvexOS

         11.0 Supports Timestamps

CRI Unicos

        8.0 Supports Timestamps

(Compaq) Digital Unix

         3.2 & 4.0 Does not support Timestamps




Thanks go out to (in no particular order)

cstone cstone () pobox com

        Solaris 2.6 box to scan
        Solaris 8 box to scan
Tim Helton thelton () 1115 net

        BSD configuration options
        Netopia scan
        IOS scan
        TCP/IP Illustrated Quote
        Proof reading
Phear jhm () santacruz org

        Linux 2.0.x kernel (who knew anyone still had one of those up :)
Storm

        BSDI box to scan
Nefarius

        For insisting that if Netcraft's uptime reports were even close
        to accurate then Windows would be at the top of the list.
        And for letting me scan your Windows 2000 box

Anyone else that knowingly or unwittingly helped me while I was ranting about
this over the last week.

## Appendix A --- Source Code

I did my testing under linux, and in order to easily retrieve the remote Timestamp I had to make a small kernel change.  Because I am running 2.4.x and a lot of people may not be I will try to document this as generically as possible, note this should work fairly easily on 2.2 kernels however your results may be different (therefore I am not responsible if you choose to do this and it breaks *anything*, use at your own risk).  I will be submitting these changes to Linux Kernel developers so that it may become part of the official release (there is no reason to deny access to the timestamp information and who knows maybe someone will use timestamps as a covert data channel :)

If these directions are not clear enough then you probably shouldn't be editing your kernel.  I could have included diffs, however 2.2 kernels are quite different so line numbers would not match, and I have other mods that would prevent patch from working correctly anyway.

Here is what I did:

All of these start at your kernel root directory (ie /usr/src/linux)

include/linux/tcp.h  -- Add the following to the section 'TCP socket options'
```
#define TCP_RCV_TIMESTAMP       12      /* The received Timestamp */
#define TCP_SND_TIMESTAMP       13      /* The sent Timestamp */
```

net/ipv4/tcp.c  -- Add to the routine tcp_getsockopt() in the select statement
```
        case TCP_RCV_TIMESTAMP:
          if (tp->tstamp_ok)
            val = tp->rcv_tsval;
          else
            val = 0;
          break;
        case TCP_SND_TIMESTAMP:
          if (tp->tstamp_ok)
            val = tp->rcv_tstamp;
          else
            val = 0;
          break;
```



remake your kernel and reboot.  Now you need a program that will connect and display the timestamps..  That is fairly straight forward now.

```
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/tcp.h>

#define TCP_RCV_TIMESTAMP 12 /* The received Timestamp */
#define TCP_SND_TIMESTAMP 13 /* The sent Timestamp */


int connserver(char *host,int port)
{
  int sd,addr,flag=1;
  struct hostent *he;
  struct sockaddr_in sa;


  /* try to resolve the host */
  if((addr=inet_addr(host))!= -1) {/* dotted decimal */
    memcpy(&sa.sin_addr,(char *)&addr,sizeof(addr));
  } else {
    if((he=gethostbyname(host))==NULL) {
      printf("Unable to resolve %s\n",host);
      return(-1);
    }
    memcpy(&sa.sin_addr,he->h_addr,he->h_length);
  }

  sa.sin_port=htons(port);
  sa.sin_family=AF_INET;

  if((sd=socket(AF_INET,SOCK_STREAM,0))<0) {
    perror("socket");
    return(-1);
  }


  /* make sure that we use timestamping if the kernel has it defaulted to not send them
   * This is not required for the linux systems I have seen as they always try to
   * negotiate timestamps if they are enabled in the kernel, but better safe than
   * wondering why it doesn't work
   */
  if(setsockopt(sd, IPPROTO_TCP, TCPOPT_TIMESTAMP, (char *) &flag, sizeof(int))<0)
    perror("setsockopt TCP_TIMESTAMP");

  if(connect(sd,(struct sockaddr *)&sa,sizeof(sa))<0) {
    perror("connect");
    exit(1);
  }
  return(sd);
}




unsigned int get_ts(char *host,int port)
{
  int optsize=sizeof(long);
  unsigned int l;
  char buff[15];
  int sd;

  if((sd=connserver(host,port))==-1) exit(0);
  if (!getsockopt(sd, IPPROTO_TCP, TCP_RCV_TIMESTAMP, &l, &optsize)) {
    if(l!=0) {
      close(sd);
      return(l);
    } else {
      /* Win2k workaround, If we are here, either the box doesnt support
       * Timestamps or its win2k which sends a 0 TS in the handshake
       */
      sprintf(buff,"ooga booga\n");
      send(sd,buff,strlen(buff),0);
      /* wait for data
       * potential problem with it hanging forever if no data is returned
       */
      while(!recv(sd,buff,sizeof(buff),0)) ;
      if (!getsockopt(sd, IPPROTO_TCP, TCP_RCV_TIMESTAMP, &l, &optsize)) {
        close(sd);
        return(l); /* 0 if remote system doesnt support Timestamping */
      } else perror("getsockopt");
    }
  } else perror("getsockopt");
  close(sd);
  return(0);
}



int main(int argc, char **argv)
{
  int ts1,ts2,tickrate;
  int sec,min,hour,day;

  if(argc!=3) {
    printf("Usage: %s <ip> <port>\n",argv[0]);
    exit(0);
  }

  ts1=get_ts(argv[1],atoi(argv[2]));
  sleep(1); /* wait for the remote system to increment the counter a bit */
  ts2=get_ts(argv[1],atoi(argv[2]));

  printf("TimeStamp1: %d\n",ts1);
  printf("TimeStamp2: %d\n",ts2);
  tickrate=(ts2-ts1);
  printf("Unmodified tickrate %d\n",tickrate);

  /* compensate for network delays +-30% */
  if(tickrate) {
    if(tickrate<1300 && tickrate > 700) tickrate=1000;
    else if(tickrate<130 && tickrate > 70) tickrate=100;
    else if(tickrate<30 && tickrate > 7) tickrate=10;
    else if(tickrate<4 && tickrate > 1) tickrate=2;
    else printf("Unknown tickrate - will try but may be incorrect\n");

    day=(ts2/tickrate)/86400;
    sec=(ts2/tickrate)%86400;
    hour=sec/3600;
    sec=sec%3600;
    min=sec/60;
    sec=sec%60;

    printf("%s (Tickrate %d/sec) Uptime: %u days, %02d:%02d:%02d\n",argv[1],tickrate,day,hour,min,sec);
  } else
    printf("The remote system does not appear to support TCP Timestamping\n");

  return(0); /* as per C89 spec main() returns an int */
}
```
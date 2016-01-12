"""
DNS Reporter tool, summarise source ip and A/PTR records
a bit like DNStop, DNSstat and others
"""
__author__      = 'Aidy'
__version__     = '1.2'

#-----------------------------------------------------------------------------#
import sys
#import curses
from blessings import Terminal

import time
import operator

import pcapy
import dpkt.dns
from impacket.ImpactDecoder import EthDecoder

DEBUG=0 #Enable debug
PACKET_COUNT=10 #Debug, capture only x packets and exit

#-----------------------------------------------------------------------------#
class ScreenDNS:
 """ Display screen
 """

 def __init__(self):
  """
  """
  self.stdscr = curses.initscr()

 def start(self):
  """ Start
  """
  self.stdscr.addstr(0,0, 'DNS Reporter - %s' % time.ctime())
  self.stdscr.addstr(1,0, 'Sniffer interface %s - Pcap filer %s' %(dns_p.s_interface,dns_p.pcapfilter))
  self.stdscr.refresh()
  na = 0 #Clear vars
  da = 0
  pre_ip_amount = 0
  pre_d_amount = 0
  a = ""
  dns_p.packet_count+=1

 def display_top_packets(self):
  """ Start
  """
  dns_p.packet_count+=1
  stdscr.addstr(2,0, 'Total number of Packets %s' % dns_p.packet_count)
  if dns_p.packet_count == dns_p.packet_dump_cnt:
    dns_p.dump_stats()

  dns_p.parse_udp_packet(packet) #Parse the packets

  stdscr.addstr(3,0, '                                                                                                                           ')
  a = ' '.join(dns_p.live_packet)
  stdscr.addstr(3,0, 'Live -> %s ' % a)
  stdscr.refresh()

 def display_top_clientip(self):
  """ Start
  """
  stdscr.addstr(5,0, 'Top %s Client IP address' % dns_p.top_ip_amount)
  (n,i) = dns_p.sorted_ip_data_cnt()
  if n > dns_p.top_ip_amount: #show top ten or whatever
   for nm in range(6,6+dns_p.top_ip_amount):
    if na != dns_p.top_ip_amount:
      tmp_i =  i[na]
      stdscr.addstr(nm,0, '                                             ')
      stdscr.addstr(nm,0, 'IP %s' %(tmp_i[0]))
      stdscr.addstr(nm,20, 'Count %s' %(tmp_i[1]))
      stdscr.refresh()
      na+=1
   else:
    pre_ip_amount = dns_p.top_ip_amount + 10 #has not hit the top amount
    stdscr.addstr(pre_ip_amount,0, 'IP -> %s %s' %(n,i))
    stdscr.refresh()

 def display_top_domains(self):
  """ Start
  """
  stdscr.addstr(5,40, 'Top %s Domains' % dns_p.top_domain_amount)
  (n,i) = dns_p.sorted_domain_data_cnt()
  if n > dns_p.top_domain_amount: #show top ten
   for dm in range(6,6+dns_p.top_domain_amount):
    if da != dns_p.top_domain_amount:
      tmp_i =  i[da]
      stdscr.addstr(dm,40, '                                                        ')
      stdscr.addstr(dm,40, '%s' %(tmp_i[0]))
      stdscr.addstr(dm,100, 'Count %s' %(tmp_i[1]))
      stdscr.refresh()
      da+=1
  else:
    pre_d_amount = dns_p.top_ip_amount + dns_p.top_domain_amount + 10
    stdscr.addstr(pre_d_amount,0, 'DNS -> %s %s' %(n,i))
    stdscr.refresh()

#-----------------------------------------------------------------------------#

class DNSprocess:
 """Class - Creates and stores dns packets into a dict
 """

 def __init__(self):
  """ Init and setup class
  """
  self.matx_s_ip = {}
  self.matx_d_domain = {}

  self.s_interface = "eth0" #Settings
  self.pcapfilter = "ip and udp and port 53"

  self.packet_count = 0
  self.packet_dump_cnt = 100
  self.packet_d_filename = "dns-rpt-dump.log"
  self.live_packet = []

  self.top_ip_amount = 20
  self.top_domain_amount = 20

 def add_recs_ip(self,s_ip,d_domain):
  """ Putting source ip and domains into dict and count
  """
  if s_ip in self.matx_s_ip: #Add in the IP
   ip_cnt = (self.matx_s_ip.get(s_ip))
   self.matx_s_ip[s_ip] = ip_cnt+1
  else:
   self.matx_s_ip[s_ip] = 1

  if d_domain in self.matx_d_domain: #Add in the domains
   domain_cnt = (self.matx_d_domain.get(d_domain))
   self.matx_d_domain[d_domain] = domain_cnt+1
  else:
   self.matx_d_domain[d_domain] = 1


 def parse_r_dns_packet(self, packet):
  """ Parse the return packet
  """
  qry = "null"

  return qry

 def parse_q_dns_packet(self, packet):
  """ Parse the original query packet
  """
  qry = "null"
  # A record, PTR records, if dst port == 53
  dns_resp = dpkt.dns.DNS(packet)

  if dns_resp.opcode == dpkt.dns.DNS_QUERY: #Filter out wierdy DNS queries
   qry = dns_resp.qd[0].name

  return qry

 def parse_udp_packet(self,packet):
  """ Parse the packets from sniffer
  """
  s = ""
  q = ""
  eth_dec = EthDecoder()

  eth_pkt = eth_dec.decode(packet) #Chain down the packets thru the stack
  ip_hdr = eth_pkt.child()
  udp_hdr = ip_hdr.child()

  if udp_hdr.get_uh_dport() == 53: #Split out query types by dst port 53
   s = ip_hdr.get_ip_src()
   q = self.parse_q_dns_packet(udp_hdr.get_data_as_string())
   #Add source ip data to dict-matrix
   self.add_recs_ip(s,q)

   self.live_packet = []
   self.live_packet.append(s)
   self.live_packet.append(q)
   #print self.live_packet

  elif udp_hdr.get_uh_sport() == 53: #inbound response backets
   s = ip_hdr.get_ip_src()
   q = self.parse_r_dns_packet(udp_hdr.get_data_as_string())
   #Add data to matrix - filter at the add_recs
   #self.add_recs_ip(s,q)

 def sorted_ip_data_cnt(self):
  """ Sorted IP data
  """
  #
  sortd_ip_cnt = sorted(self.matx_s_ip.items(),key=operator.itemgetter(1),reverse=True)
  sortd_ip_num = len(sortd_ip_cnt)
  #print "-> ",sortd_ip_cnt, "->>", sortd_ip_num

  return(sortd_ip_num, sortd_ip_cnt)

 def sorted_domain_data_cnt(self):
  """ Sorted domain data
  """
  #
  sortd_domain_cnt = sorted(self.matx_d_domain.items(),key=operator.itemgetter(1),reverse=True)
  sortd_domain_num = len(sortd_domain_cnt)
  #print "-> ",sortd_domain_cnt, "->>", sortd_domain_num

  return(sortd_domain_num, sortd_domain_cnt)


 def dump_stats(self):
  """ Dump out stats and defined intervals
  """
  try:
   dump_file = open(self.packet_d_filename, "rw+") #open file

   dump_file.write("DNS Reporter Dump " + time.ctime() + "\n")
   dump_file.write("interface " + self.s_interface + "\n")
   dump_file.write("Pcap filter " + self.pcapfilter + "\n")
   dump_file.write("Packet Count " + str(self.packet_count) + "\n")
   dump_file.write("Top IP amount " + str(self.top_ip_amount) + "\n" + "Top Domain amount " + str(self.top_domain_amount) + "\n")

   dump_file.writelines('{0}:{0}'.format(k,v) for k,v in self.matx_s_ip.items())
   dump_file.write("\n")
   dump_file.writelines('{0}:{0}'.format(k,v) for k,v in self.matx_d_domain.items())
   dump_file.write("\n")

   dump_file.write("" + "\n")
   dump_file.close() #Close file

  except IOError, message: # file read failed
   print "The Dump file ", self.packet_d_filename, " could not be opened :", message
   raise

 def dump_stats_log(self, packet):
  """ Dump out stats
  """
  s = ""
  q = ""
  eth_dec = EthDecoder()
  eth_pkt = eth_dec.decode(packet) #Chain down the packets thru the stack
  ip_hdr = eth_pkt.child()
  udp_hdr = ip_hdr.child()

  if udp_hdr.get_uh_dport() == 53: #Split out query types by dst port 53
   s = ip_hdr.get_ip_src()
   q = self.parse_q_dns_packet(udp_hdr.get_data_as_string())
   print "DNS - query inbound ", s, q

  elif udp_hdr.get_uh_sport() == 53: #inbound response backets
   s = ip_hdr.get_ip_src()
   q = self.parse_r_dns_packet(udp_hdr.get_data_as_string())
   print "DNS - return ", s, q

#-----------------------------------------------------------------------------#
def main(argv):
 """ Main code
 """
 #
 dns_p = DNSprocess()

 cap = pcapy.open_live(dns_p.s_interface, 65536 , 1 , 0) #setup the sniffer interface
 cap.setfilter(dns_p.pcapfilter) #pcap filter
 print "DNS Reporter Dump " + time.ctime()
 print "Interface " + dns_p.s_interface + "Pcap filter " + dns_p.pcapfilter

 term = Terminal()
 print 'I am ' + term.bold + 'bold' + term.normal + '!'

 #Lets start sniffing packets
 while True:
  try:
   (header, packet) = cap.next()

  except pcapy.PcapError:
   continue #need todo this waiting for some traffic to process

  else:
   dns_p.dump_stats_log(packet) #Parse the packets

 #date/time, client-ip, record-type, domain-name

#-----------------------------------------------------------------------------#
if __name__ == '__main__':
 main(sys.argv)

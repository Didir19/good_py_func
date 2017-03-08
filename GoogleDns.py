__author__ = 'ecaltum'
import dns.resolver

answers = dns.resolver.query('_cloud-netblocks.googleusercontent.com.', 'TXT')
for rdata in answers:
    for txt_string in rdata.strings:
      a=txt_string.split(" ")
      for line in a:
          if "include" in line:
              b= line.split(':')

              answers2=dns.resolver.query(b[1]+'.', 'TXT')
              for rdata2 in answers2:
                  for txt_string1 in rdata2.strings:
                      d=txt_string1.split(" ")
                      for line in d:
                          if "ip" in line:
                              print line
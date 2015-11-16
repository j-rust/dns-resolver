import sys
import dns.message
import dns.query
import dns.name
import time
import socket

class Resolver():

    def __init__(self):
        self.referral_cache = {}
        self.answer_cache = {}
        # cache initialization is hardcoded currently, may want to make it dynamic
        self.referral_cache['.'] = {}
        self.referral_cache['.']['NS'] = ['a.root-servers.net.', 'b.root-servers.net.', 'c.root-servers.net.']

        self.referral_cache['a.root-servers.net.'] = {}
        self.referral_cache['a.root-servers.net.']['A'] = ['198.41.0.4']
        self.referral_cache['b.root-servers.net.'] = {}
        self.referral_cache['b.root-servers.net.']['A'] = ['192.228.79.201']
        self.referral_cache['c.root-servers.net.'] = {}
        self.referral_cache['c.root-servers.net.']['A'] = ['192.33.4.12']
        self.referral_cache['d.root-servers.net.'] = {}
        self.referral_cache['d.root-servers.net.']['A'] = ['199.7.91.13']

        self.referral_cache['a.root-servers.net.']['AAAA'] = ['2001:0503:ba3e:0000:0000:0000:0002:0030']

    #  q is the web address, record is the record type (A, AAAA), server is IP address of server to query
    def execute_query(self, q, record, server):
        query = dns.message.make_query(q, record)
        return dns.query.udp(query, server)

    def resolve(self, domain, rrtype):
        print 'Received resolve command with args: ' + domain + ' ' + rrtype
        ip_address_server_list = self.referral_cache['a.root-servers.net.'][rrtype]
        ip_address_of_server_to_use = ip_address_server_list[0]
        found_ip = False

        while not found_ip:
            query_result = self.execute_query(domain, rrtype, ip_address_of_server_to_use)

            if not query_result.answer:
                print 'Do not have an answer'
                if rrtype == 'A':
                    ip_address_of_server_to_use = self.getNextServersIPForATypeRecord(query_result)
                elif rrtype == 'AAAA':
                    ip_address_of_server_to_use = self.getNextServersIPForAAAATypeRecord(query_result)

            else:
                print 'Found answer for ' + domain + ' with rrtype ' + rrtype
                print self.getFinalIPOfATypeRecord(query_result, rrtype)
                found_ip = True

        return 0


    def getNextServersIPForATypeRecord(self, query_result):
        print 'Attempting to resolve A type domain'
        #query_result.additional looks like "m.gtld-servers.net. 172800 IN A 192.55.83.30"
        #Take the first server and grab its IP address
        query_result_tokens = str(query_result.additional[0]).split(" ")
        return query_result_tokens[4]

    def getNextServersIPForAAAATypeRecord(self, query_result):
        print 'Attempting to resolve AAAA type domain'
        #query_result.additional looks like "m.gtld-servers.net. 172800 IN A 192.55.83.30"
        #Take the first server and grab its IP address
        query_result_tokens = str(query_result.additional[0]).split(" ")
        return query_result_tokens[4]

    def getFinalIPOfATypeRecord(self, query_result, rrtype):
        if rrtype == 'A':
            answer_tokens = str(query_result.answer[0]).split(" ")
            return answer_tokens[4]
        elif rrtype == 'AAAA':
            answer_tokens = str(query_result.answer[0]).split(" ")
            return answer_tokens[4]



    def print_referral_cache(self):
        for domain in self.referral_cache:
                print domain + " :"
                for key in self.referral_cache[domain]:
                    list = ', '.join(self.referral_cache[domain][key])
                    print key + " : [" + list + "]"
                print ""

    def print_answer_cache(self):
        for domain in self.answer_cache:
                print domain + ":"
                for key in self.answer_cache[domain]:
                    list = ', '.join(self.answer_cache[domain][key])
                    print key + ": [" + list + "]"
                print ""

    def print_cache(self):
        print 'Cache Contents:'
        print ''
        self.print_referral_cache()
        self.print_answer_cache()

    def process_command(self, cmd):
        cmd_tokens = cmd.split(" ")
        if cmd_tokens[0] == 'resolve':
            self.resolve(cmd_tokens[1], cmd_tokens[2])
        elif cmd == 'print cache':
            self.print_cache()
        elif cmd == 'quit':
            sys.exit(0)
        else:
            print "Unable to recognize command: " + cmd


    def read_file(self, filename):
        file = open(filename)
        for line in file:
            self.process_command(line.strip())



if __name__ == "__main__":
    filename = sys.argv[1]
    resolver = Resolver()
    resolver.read_file(filename)

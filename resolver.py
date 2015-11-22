import sys
import dns.message
import dns.query
import dns.name
import dns.rdtypes
import dns.resolver
import dns.rdata
import time
import socket

from dns import rdatatype


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

    #  q is the web address, record is the record type (A, AAAA), server is IP address of server to query
    def execute_query(self, q, record, server):
        query = dns.message.make_query(q, record, want_dnssec=True)
        return dns.query.udp(query, server)

    def get_ns_records(self, domain):
        domain += '.'
        checks = domain.count('.') + 1
        check_count = 0
        while check_count < checks:
            if domain in self.referral_cache:
                break
            else:
                index = domain.find('.') + 1
                domain = domain[index:]
                if domain == '':
                    domain = '.'
            check_count += 1

        return self.referral_cache[domain]['NS']

    def resolve(self, domain, rrtype):
        print 'Received resolve command with args: ' + domain + ' ' + rrtype
        # ip_address_server_list = self.referral_cache['a.root-servers.net.']['A']
        # ip_address_of_server_to_use = ip_address_server_list[0]
        ns_list = self.get_ns_records(domain)
        ip_address_of_server_to_use = self.referral_cache[ns_list[0]]['A'][0]
        found_ip = False

        if domain in self.answer_cache:
            if rrtype in self.answer_cache[domain]:
                return self.answer_cache[domain][rrtype]


        while not found_ip:
            query_result = self.execute_query(domain, rrtype, ip_address_of_server_to_use)
            print query_result
            rcode = query_result.rcode()
            if rcode != dns.rcode.NOERROR:
                if rcode == dns.rcode.NXDOMAIN:
                    print 'NXDOMAIN Error: ' + domain + ' does not exist'
                    break
                if rcode == dns.rcode.REFUSED:
                    print 'Error, domain could not be resolved: ' + domain
                    break
                if rcode == dns.rcode.SERVFAIL:
                    print 'SERVFAIL Error: ' + domain
                    break

            if query_result.answer:
                rr = query_result.answer[0][0]
            else:
                rr = query_result.authority[0][0]
            if rr.rdtype == dns.rdatatype.SOA:
                print query_result.__str__()
                break

            if not query_result.answer:
                print 'Do not have an answer'
                ref_domain = str(query_result.authority[0]).split(" ")[0]
                if rrtype == 'A':
                    ip_address_of_server_to_use, ref_server = self.getNextServersIPForATypeRecord(query_result)
                elif rrtype == 'AAAA':
                    ip_address_of_server_to_use, ref_server = self.getNextServersIPForAAAATypeRecord(query_result)
                elif rrtype == 'MX':
                    ip_address_of_server_to_use, ref_server = self.getNextServersIPForMXTypeRecord(query_result)
                elif rrtype == 'TXT':
                    ip_address_of_server_to_use, ref_server = self.getNextServersIPForTXTTypeRecord(query_result)
                if ref_domain not in self.referral_cache:
                    self.referral_cache[ref_domain] = {}
                if 'NS' not in self.referral_cache[ref_domain]:
                    self.referral_cache[ref_domain]['NS'] = []
                self.referral_cache[ref_domain]['NS'].append(ref_server)
                if ref_server not in self.referral_cache:
                    self.referral_cache[ref_server] = {}
                if 'A' not in self.referral_cache[ref_server]:
                    self.referral_cache[ref_server]['A'] = []
                self.referral_cache[ref_server]['A'].append(ip_address_of_server_to_use)
            else:
                print 'Found answer for ' + domain + ' with rrtype ' + rrtype
                if domain not in self.answer_cache:
                    self.answer_cache[domain] = {}
                if rrtype not in self.answer_cache[domain]:
                    self.answer_cache[domain][rrtype] = []
                if self.checkIfAnswerContainsCNAME(query_result) == True:
                    found_ip == False
                    final_ip = self.getFinalIPOfRecord(query_result, rrtype)
                    self.answer_cache[domain][rrtype].append(final_ip)
                    query_result_tokens = str(query_result.answer[0]).split(" ")
                    ip_address_of_server_to_use = self.referral_cache[ns_list[0]]['A'][0]
                    domain = query_result_tokens[4]
                else:
                    final_ip = self.getFinalIPOfRecord(query_result, rrtype)
                    print final_ip
                    self.answer_cache[domain][rrtype].append(final_ip)
                    found_ip = True

        return 0


    def getNextServersIPForATypeRecord(self, query_result):
        print 'Attempting to resolve A type domain'
        #query_result.additional looks like "m.gtld-servers.net. 172800 IN A 192.55.83.30"
        #Take the first server and grab its IP address
        for i in range(0, 5):
            query_result_tokens = str(query_result.additional[i]).split(" ")
            if query_result_tokens[3] == 'A':
                break
        return query_result_tokens[4], query_result_tokens[0]

    def getNextServersIPForAAAATypeRecord(self, query_result):
        print 'Attempting to resolve AAAA type domain'
        #query_result.additional looks like "m.gtld-servers.net. 172800 IN A 192.55.83.30"
        #Take the first server and grab its IP address
        query_result_tokens = str(query_result.additional[0]).split(" ")
        return query_result_tokens[4], query_result_tokens[0]

    def getNextServersIPForMXTypeRecord(self, query_result):
        print 'Attempting to resolve MX type domain'
        query_result_tokens = str(query_result.additional[0]).split(" ")
        return query_result_tokens[4], query_result_tokens[0]

    def getNextServersIPForTXTTypeRecord(self, query_result):
        print 'Attempting to resolve TXT type domain'
        #query_result.additional looks like "m.gtld-servers.net. 172800 IN A 192.55.83.30"
        #Take the first server and grab its IP addresss
        query_result_tokens = str(query_result.additional[0]).split(" ")
        return query_result_tokens[4], query_result_tokens[0]

    def getFinalIPOfRecord(self, query_result, rrtype):
        if rrtype == 'A':
            answer_tokens = str(query_result.answer[0]).split(" ")
            #if str(query_result.answer[0]).find('CNAME'):print 'Contains cname'
            return answer_tokens[4].split()[0]
        elif rrtype == 'AAAA':
            answer_tokens = str(query_result.answer[0]).split(" ")
            return answer_tokens[4]
        elif rrtype == 'MX':
            answer_tokens = str(query_result.answer[0]).split(" ")
            return answer_tokens[5]
        elif rrtype == 'TXT':
            print 'Answer for txt is:'
            answer_tokens = str(query_result.answer[0]).split(" ")
            split_answer_tokens = answer_tokens[5].split(":")
            return split_answer_tokens[1]


    def checkIfAnswerContainsCNAME(self, query_result):
        print 'Checking for CNAME'
        print str(query_result.answer[0])
        if 'CNAME' in str(query_result.answer[0]):
            print 'Contains CNAME'
            print query_result.answer[0]
            return True
        else:
            print 'Does not contain CNAME'
            return False

    def print_referral_cache(self):
        print 'Referral Cache Contents:\n'
        for domain in self.referral_cache:
                print domain + " :"
                for key in self.referral_cache[domain]:
                    print key + ' : ' + self.referral_cache[domain][key].__str__()
                print ""

    def print_answer_cache(self):
        print 'Answer Cache Contents:\n'

        for domain in self.answer_cache:
                print domain + " :"
                for key in self.answer_cache[domain]:
                    print key + ' : ' + self.answer_cache[domain][key].__str__()
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

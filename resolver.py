import sys
import dns.message
import dns.query
import dns.name
import dns.rdtypes
import dns.resolver
import dns.rdata
import dns.exception
from dns.exception import DNSException
import time

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
    def execute_query(self, q, record, server, original_domain):
        if original_domain == '': print 'COMMAND resolve ' + q + ' ' + record
        else: print 'COMMAND resolve ' + original_domain + ' ' + record
        query = dns.message.make_query(q, record, want_dnssec=True)

        #return dns.query.udp(query, server, timeout=2)
        for i in range (0, 3):
            try:
                return dns.query.udp(query, server, timeout=2)
            except dns.exception.Timeout:
                print 'Attempting to resolve ' + q + ' for the ' + str(i + 1) + ' time'
        print 'could not resolve ' + q + ' due to timeout error'


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
        ns_list = self.get_ns_records(domain)
        ip_address_of_server_to_use = self.referral_cache[ns_list[0]]['A'][0]
        print '*** NS records fetched from cache: ' + ns_list.__str__()
        print '*** Name server ' + ns_list[0].__str__() + ' has IP address ' + \
              self.referral_cache[ns_list[0]]['A'].__str__()
        found_ip = False
        cname_info_to_append_to_answer = []

        start_time = time.clock()
        if domain in self.answer_cache:
            if rrtype in self.answer_cache[domain]:
                stop_time = time.clock()
                print 'Found answer in answer cache'
                print self.answer_cache[domain][rrtype]
                print 'Total latency: ' + str((stop_time - start_time) * 1000) + ' milliseconds'
                return self.answer_cache[domain][rrtype]
        stop_time = time.clock()
        total_time = stop_time - start_time

        cname_chase = False
        original_domain = ""

        while not found_ip:
            start_time = time.clock()
            query_result = self.execute_query(domain, rrtype, ip_address_of_server_to_use, original_domain)
            stop_time = time.clock()
            if(dns.flags.AA) and not query_result.answer:
                if domain not in self.answer_cache:
                    self.answer_cache[domain] = {}
                self.answer_cache[domain][rrtype] = query_result
                print query_result
                total_time += (stop_time - start_time)
                print 'Total latency: ' + str(total_time * 1000) + ' milliseconds'
                print '***************************************************'
                break


            if not query_result: break
            print query_result
            rcode = query_result.rcode()
            if rcode != dns.rcode.NOERROR:
                if rcode == dns.rcode.NXDOMAIN:
                    print 'NXDOMAIN Error: ' + domain + ' does not exist'
                    self.answer_cache[domain] = {}
                    self.answer_cache[domain][rrtype] = query_result
                    break
                if rcode == dns.rcode.REFUSED:
                    print 'Error, domain could not be resolved: ' + domain
                    self.answer_cache[domain] = {}
                    self.answer_cache[domain][rrtype] = query_result
                    break
                if rcode == dns.rcode.SERVFAIL:
                    print 'SERVFAIL Error: ' + domain
                    self.answer_cache[domain] = {}
                    self.answer_cache[domain][rrtype] = query_result
                    break

            if query_result.answer:
                rr = query_result.answer[0][0]
            else:
                rr = query_result.authority[0][0]
            if rr.rdtype == dns.rdatatype.SOA:
                print query_result.__str__()
                break

            total_time += (stop_time - start_time)
            if not query_result.answer:
                for server in query_result.additional:
                    ref_domain = str(query_result.authority[0]).split(" ")[0]
                    #ip_address_of_server_to_use, ref_server = self.getNextServer(query_result)
                    ref_server = str(server).split(" ")[0]
                    ip_address_of_server_to_use = str(server).split(" ")[4]
                    type_of_record_to_add = str(server).split(" ")[3]
                    #print ip_address_of_server_to_use
                    if ref_domain not in self.referral_cache:
                        self.referral_cache[ref_domain] = {}
                    if 'NS' not in self.referral_cache[ref_domain]:
                        self.referral_cache[ref_domain]['NS'] = []
                    if ref_server not in self.referral_cache[ref_domain]['NS']: self.referral_cache[ref_domain]['NS'].append(ref_server)
                    if ref_server not in self.referral_cache:
                        self.referral_cache[ref_server] = {}
                    if type_of_record_to_add not in self.referral_cache[ref_server]:
                        self.referral_cache[ref_server][type_of_record_to_add] = []
                    if ip_address_of_server_to_use not in self.referral_cache[ref_server][type_of_record_to_add]: self.referral_cache[ref_server][type_of_record_to_add].append(ip_address_of_server_to_use)
                #Add NSEC3, DS, and RRSIG records
                for server in query_result.authority:
                    ref_domain = str(query_result.authority[0]).split(" ")[0]
                    #ip_address_of_server_to_use, ref_server = self.getNextServer(query_result)
                    ref_server = str(server).split(" ")[0]
                    type_of_record = str(server).split(" ")[3]
                    if type_of_record == 'RRSIG' or type_of_record == 'DS' or type_of_record == 'NSEC3':

                        if ref_domain not in self.referral_cache:
                            self.referral_cache[ref_domain] = {}
                        if 'NS' not in self.referral_cache[ref_domain]:
                            self.referral_cache[ref_domain]['NS'] = []
                        #self.referral_cache[ref_domain]['NS'].append(ref_server)
                        if ref_server not in self.referral_cache:
                            self.referral_cache[ref_server] = {}
                        if 'A' not in self.referral_cache[ref_server]:
                            self.referral_cache[ref_server][type_of_record] = []
                        if str(type_of_record) not in self.referral_cache[ref_server][type_of_record] and type_of_record == 'NSEC3':
                            tmp = str(server).split(" ")
                            string = ' '
                            string = string.join(tmp[4:])
                            #self.referral_cache[ref_server][type_of_record].append(str(server).split(" ")[3:])
                            self.referral_cache[ref_server][type_of_record].append(string)
                        if str(type_of_record) not in self.referral_cache[ref_server][type_of_record] and type_of_record == 'RRSIG':
                            tmp = str(server).split(" ")
                            string = ' '
                            string = string.join(tmp[4:])
                            #self.referral_cache[ref_server][type_of_record].append(str(server).split(" ")[3:])
                            self.referral_cache[ref_server][type_of_record].append(string)
                        if str(type_of_record) not in self.referral_cache[ref_server][type_of_record] and type_of_record == 'DS':
                            tmp = str(server).split(" ")
                            string = ' '
                            string = string.join(tmp[4:])
                            #self.referral_cache[ref_server][type_of_record].append(str(server).split(" ")[3:])
                            self.referral_cache[ref_server][type_of_record].append(string)
                ref_domain = str(query_result.authority[0]).split(" ")[0]
                ip_address_of_server_to_use, ref_server = self.getNextServer(query_result)
                if ref_domain not in self.referral_cache:
                    self.referral_cache[ref_domain] = {}
                if 'NS' not in self.referral_cache[ref_domain]:
                    self.referral_cache[ref_domain]['NS'] = []
                if ref_server not in self.referral_cache[ref_domain]['NS']:
                    self.referral_cache[ref_domain]['NS'].append(ref_server)
                if ref_server not in self.referral_cache:
                    self.referral_cache[ref_server] = {}
                if 'A' not in self.referral_cache[ref_server]:
                    self.referral_cache[ref_server]['A'] = []
                if ip_address_of_server_to_use not in self.referral_cache[ref_server]['A']:
                    self.referral_cache[ref_server]['A'].append(ip_address_of_server_to_use)
                print 'Latency for this iteration: ' +  str((stop_time - start_time) * 1000) \
                      + ' milliseconds'
                print '_____________________________________________________'
            else:
                print 'Found answer for ' + domain + ' with rrtype ' + rrtype
                if self.checkIfAnswerContainsCNAME(query_result) == True:
                    """
                        Does the following statement have any purpose?
                        If not we should delete it
                    """
                    found_ip == False
                    final_ip = self.getFinalIPOfRecord(query_result, rrtype)
                    cname_info_to_append_to_answer.append(query_result.answer)
                    query_result_tokens = str(query_result.answer[0]).split(" ")
                    if not cname_chase:
                        original_domain = domain
                        if original_domain not in self.answer_cache:
                            self.answer_cache[original_domain] = {}
                    domain = query_result_tokens[4]
                    ns_list = self.get_ns_records(domain)
                    ip_address_of_server_to_use = self.referral_cache[ns_list[0]]['A'][0]
                    cname_chase = True
                else:
                    if cname_chase:
                        for cname_info in cname_info_to_append_to_answer:
                            query_result.answer.extend(cname_info)
                        # Remove duplicates from list
                        tmpList = []
                        for i in query_result.answer:
                            if i not in tmpList:
                                tmpList.append(i)
                        query_result.answer = tmpList
                        self.answer_cache[original_domain][rrtype] = query_result
                        found_ip = True
                    else:
                        if domain not in self.answer_cache:
                            self.answer_cache[domain] = {}
                        final_ip = self.getFinalIPOfRecord(query_result, rrtype)
                        print final_ip
                        self.answer_cache[domain][rrtype] = query_result
                        found_ip = True
                    print 'Total latency: ' + str(total_time * 1000) + ' milliseconds'
                    print '***************************************************'

        return 0


    def getNextServer(self, query_result):
        for i in range(0, 5):
            query_result_tokens = str(query_result.additional[i]).split(" ")
            if query_result_tokens[3] == 'A':
                break
        return query_result_tokens[4], query_result_tokens[0]

    def getFinalIPOfRecord(self, query_result, rrtype):
        if rrtype == 'A':
            answer_tokens = str(query_result.answer[0]).split(" ")
            return answer_tokens[4].split()[0]
        elif rrtype == 'AAAA':
            answer_tokens = str(query_result.answer[0]).split(" ")
            return answer_tokens[4]
        elif rrtype == 'MX':
            answer_tokens = str(query_result.answer[0]).split(" ")
            return answer_tokens[5]
        elif rrtype == 'TXT':
            answer_tokens = str(query_result.answer[0]).split(" ")
            split_answer_tokens = answer_tokens[5].split(":")
            return split_answer_tokens[1]


    def checkIfAnswerContainsCNAME(self, query_result):
        print str(query_result.answer[0])
        if 'CNAME' in str(query_result.answer[0]):
            print query_result.answer[0]
            return True
        else:
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
                for rrtype in self.answer_cache[domain]:
                    print rrtype + ' : ' + self.answer_cache[domain][rrtype].__str__()
                    print ''
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

    """
        The following are stopwatch type methods to keep track of time
    """
    def start(self):
        self.start_time = time.now()
        return self.start

    def stop(self):
        self.stop_time = time.now()
        self.elapsed = (self.stop_time - self.start_time) / 1000

    def reset(self):
        self.elapsed = 0.0



if __name__ == "__main__":
    filename = sys.argv[1]
    resolver = Resolver()
    resolver.read_file(filename)

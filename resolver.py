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

    #  q is the web address, record is the record type (A, AAAA), server is IP address of server to query
    def execute_query(self, q, record, server):
        query = dns.message.make_query(q, record)
        return dns.query.udp(query, server)

    def resolve(self, domain, rrtype):
        print 'Received resolve command with args: ' + domain + ' ' + rrtype
        name_server = self.referral_cache['a.root-servers.net.']['A'];
        flag = False
        counter = 0
        current_name_server = None
        while(counter < 5):
            print 'Name server is:'
            print name_server[0]
            query_result = self.execute_query(domain, rrtype, name_server[0])
            #print 'Authority resultOne'
            #print query_result.authority
            #print 'Additional resultOne'
            #print query_result.additional
            #print 'Answer resultOne'
            #print query_result.answer

            authority_result = query_result.authority
            additional_result = query_result.additional
            answer_result = query_result.answer

            if not answer_result:
                print 'Have not found answer yet.'
                print 'additional_result[0] is:'
                print additional_result[0]
                current_name_server = str(additional_result[0]).split(" ")
                print 'New server name is:'
                print current_name_server[0]
                name_server[0] = current_name_server[4]
                print 'IP address of current name server is:'
                print current_name_server[4]
            else:
                print 'Found answer.'
                print answer_result
                final_answer_result = str(answer_result[0]).split(" ")
                print 'IP of domain is'
                if(rrtype == 'A' or rrtype == 'AAAA'):
                    print final_answer_result[4]
                    break
                elif(rrtype == 'MX'):
                    print 'final_answer_result[5:]'
                    print final_answer_result[5]
                    print final_answer_result
                    current_name_server = str(additional_result[0]).split(" ")
                    print 'current_name_server:'
                    name_server[0] = current_name_server[4]
                    #domain = final_answer_result[5]
                    rrtype = 'A'
                    flag = False

                else: print 'Unknown rrtype'



            ### Three lines below get the ip address of whatever domain name we pass in.  So does above code but I
            ### am not positive that the indexes will never change
            #addr_info = socket.getaddrinfo(domain, 53, 0, 0, socket.IPPROTO_TCP)
            # IP address of nameserver
            #addr_info[1][4][0]

            print 'counter is ' + str(counter)

            counter += 1

            print '*************************END OF LOOP ITERATION*************************'

        return 0

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

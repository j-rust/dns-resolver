import sys
import dns.message
import dns.query
import dns.name
import time

class Resolver():

    def __init__(self):
        self.referral_cache = {}
        self.answer_cache = {}
        # cache initialization is hardcoded currently, may want to make it dynamic
        self.answer_cache['.'] = {}
        self.answer_cache['.']['NS'] = ['a.root-servers.net.', 'b.root-servers.net.', 'c.root-servers.net.']

        self.referral_cache['a.root-servers.net.'] = {}
        self.referral_cache['a.root-servers.net.']['A'] = ['198.41.0.4']
        self.referral_cache['a.root-servers.net.']['AAAA'] = ['2001:503:ba3e::2:30']
        self.referral_cache['b.root-servers.net.'] = {}
        self.referral_cache['b.root-servers.net.']['A'] = ['192.228.79.201']
        self.referral_cache['c.root-servers.net.'] = {}
        self.referral_cache['c.root-servers.net.']['A'] = ['192.33.4.12']
        self.referral_cache['d.root-servers.net.'] = {}
        self.referral_cache['d.root-servers.net.']['A'] = ['199.7.91.13']

    def execute_query(self, q, record, server):
        query = dns.message.make_query(q, record)
        return dns.query.udp(query, server)

    def resolve(self, cmd):
        print 'Received resolve command with args: ' + cmd
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
            self.resolve(cmd)
        elif cmd == 'print cache':
            self.print_cache()
        elif cmd == 'quit':
            print 'Quitting'
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

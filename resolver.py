import sys
import dns.message
import dns.query
import dns.name

class Resolver():

    def __init__(self):
        self.cach = None

    def resolve(self, cmd):
        print 'Received resolve command with args: ' + cmd
        return 0

    def print_cache(self):
        print 'No cache to print'
        return 0

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

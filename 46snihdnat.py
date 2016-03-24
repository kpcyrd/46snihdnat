#!/usr/bin/env python3
import sys
import re

opts = dict(
    origin='hamburgmesh.net.',
    ttl=1800,
    ns='46ns.rxv.cc.',
    admin='admin.rxv.cc.',
    serial='2016010101',
    refresh=3600,
    retry=900,
    expire=1209600
)

env = {
    '$SNI': '46.101.199.212'
}


head = '''$ORIGIN {origin}
$TTL {ttl}

@           IN      SOA     {ns}        {admin} (
                                        {serial}                ; serial
                                        {refresh}               ; refresh
                                        {retry}                 ; retry
                                        {expire}                ; expire
                                        {ttl}                   ; ttl
                                        )
'''.format(**opts)


def parse(fp, env={}):
    for line in fp:
        line = line.strip()

        if not line or line.startswith('#'):
            continue

        tokens = re.split('\s+', line)
        tokens = map(lambda x: env[x] if x in env else x, tokens)
        try:
            name, rtype, addr = tokens
            if rtype == '%':
                for rtype, addr in [('A', env['$SNI']), ('AAAA', addr)]:
                    yield name, rtype, addr
            else:
                yield name, rtype, addr
        except ValueError:
            pass


FMT = '%-28s IN %-6s %s'


def main():
    print(head)
    for zone in sys.argv[1:]:
        for line in parse(open(zone), env):
            print(FMT % line)


if __name__ == '__main__':
    main()

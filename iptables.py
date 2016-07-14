'''
iptables parser
tested on RHEL6
'''
import re
import os 
from pprint import pprint

from addict import Dict         # pip install addict



def parse(output):
    ''' get iptabls structure from iptables command output
    returns an hash: 
     { 
        "INPUT": {
          "policy": "DROP",
          "rules": [list of rules]
        },
        ...
     }
    '''
    chains = Dict()
    current_chain = None
    current_chain_name = None
    for line in output.splitlines() + ['EOF']:
        if line.startswith('Chain') or line.startswith('EOF'):
            if current_chain_name and current_chain: 
                chains[current_chain_name] = current_chain
            if line.startswith('EOF'): 
                break
            match = re.match('Chain (?P<chain>\w+) \(policy (?P<policy>\w+)\)', line)
            assert match, 'regexp issue. line=%s' % line
            current_chain_name = match.groupdict()['chain']
            current_chain = Dict({'rules': Dict(), 'policy': match.groupdict()['policy'] })
        elif line.startswith('target') or not line:
            continue
        else:
            match = re.match('''
            ^
                (?P<target>ACCEPT|DROP|QUEUE|RETURN)\s+?        # ex: ACCEPT                  
                (?P<protocol>tcp|udp|icmp|all)\s+?              # ex: tcp 
                (?P<opt>\-\-|\w+)\s+?                           # ex: --
                (?P<source>\w+?|[\d.\/]+)\s+?                   # ex: 0.0.0.0/0
                (?P<destination>\w+?|[\d.\/]+)\s+               # ex: 0.0.0.0/0
                (?P<info>.+?)\s+?                               # ex: tcp dpts:9101:9103
                \/\*\s(?P<comment>.+)\s\*\/                     # ex: /* 0100 Bacula Server from anywhere */ 
            $
            ''', line,  re.VERBOSE)
            assert match, 'regex failed on line = %s' % line
            rule = Dict(match.groupdict())

            # clean up info 
            if rule.info.startswith(rule.protocol):
                rule.info = rule.info[len(rule.protocol) + 1:]

            # extract more info from info 
            match = re.match('''(dpts|dpt)\:(?P<dports>[\d\:,]+)''', rule.info,  re.VERBOSE)
            if  match: 
                rule.info = rule.info.replace(match.group(), '')
                rule.dports = match.groupdict()['dports']
            if not rule.info.strip(): 
                del rule.info 
            name = rule.comment if rule.comment else line 
            current_chain.rules[name] = rule

    return chains
    

EXAMPLE1 = '''
Chain INPUT (policy DROP)
target     prot opt source               destination
ACCEPT     icmp --  0.0.0.0/0            0.0.0.0/0           icmp type 8 /* 0001 input */
ACCEPT     icmp --  0.0.0.0/0            0.0.0.0/0           icmp type 0 /* 0002 input */
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0           state RELATED,ESTABLISHED /* 0003 input */
ACCEPT     all  --  0.0.0.0/0            127.0.0.1           /* 0004 input */
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0           tcp dpt:9102 /* 0100 Bacula Client from anywhere */
ACCEPT     tcp  --  172.21.0.0/16        0.0.0.0/0           tcp dpts:9101:9103 /* 0100 Bacula Server from anywhere */
ACCEPT     tcp  --  172.22.0.0/16        0.0.0.0/0           tcp dpts:9101:9103 /* 0100 Bacula Server from anywhere */
ACCEPT     tcp  --  172.24.0.0/16        0.0.0.0/0           tcp dpts:9101:9103 /* 0100 Bacula Server from anywhere */
ACCEPT     tcp  --  192.168.92.0/22      0.0.0.0/0           tcp dpts:9101:9103 /* 0100 Bacula Server from anywhere */
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0           tcp dpt:5666 /* 0100 NRPE */
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0           tcp dpt:22 /* 0100 SSH */
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0           tcp dpt:22 /* 0199 SSH from everwhere (default) */

Chain FORWARD (policy DROP)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     icmp --  0.0.0.0/0            0.0.0.0/0           icmp type 8 /* 0001 output */
ACCEPT     icmp --  0.0.0.0/0            0.0.0.0/0           icmp type 0 /* 0002 output */
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0           /* 0003 output */
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0           state NEW,RELATED,ESTABLISHED /* 9999 output */
'''


def test_dport_implemented():
    assert parse(EXAMPLE1).INPUT.rules['0100 Bacula Server from anywhere'].dports == '9101:9103'
    assert parse(EXAMPLE1).INPUT.rules['0100 NRPE'].dports == '5666'

def test_protocol_implemented():
    assert parse(EXAMPLE1).OUTPUT.rules['0002 output'].protocol == 'icmp'

def test_policy_implemented():
    assert parse(EXAMPLE1).OUTPUT.policy == 'ACCEPT'

if __name__ == '__main__':
    import pytest
    pytest.main( __file__.replace('\\', '/') +' -vv')

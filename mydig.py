from __future__ import print_function
import time
import datetime
import math
import sys
import dns.resolver
import copy
import dns.dnssec
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query

root_server = ['a.root-servers.net', 'b.root-servers.net', 'c.root-servers.net',
               'd.root-servers.net', 'e.root-servers.net', 'f.root-servers.net',
               'g.root-servers.net', 'h.root-servers.net', 'i.root-servers.net',
               'j.root-servers.net', 'k.root-servers.net', 'l.root-servers.net',
               'm.root-servers.net']

root_server_ip = ['198.41.0.4', '192.228.79.201', '192.33.4.12', '199.7.91.13',
                  '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53',
                  '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42',
                  '202.12.27.33']

ANSWER = 1
AUTHORITY = 2
ADDITIONAL = 3

def query_type(s_query):
    if s_query == 'A':
        return dns.rdatatype.A
    if s_query == 'NS':
        return dns.rdatatype.NS
    if s_query == 'MX':
        return dns.rdatatype.MX

    return dns.rdatatype.CNAME


#   Returns a item list (i.e: ip_address, NS, MX)
def get_result(items, section_type, rdtype):
    ret = []
    for item in items:
        if section_type == ANSWER:
            if item.rdtype != rdtype:
                continue
            if rdtype == query_type('NS') or rdtype == query_type('CNAME'):
                ret.append(str(item.target))
            elif rdtype == query_type('A'):
                ret.append(str(item.address))
            elif rdtype == query_type('MX'):
                ret.append(str(item.exchange))
        elif section_type == AUTHORITY:
            ret.append(str(item.target))
        elif section_type == ADDITIONAL:
            if item.rdtype == query_type('A'):
                ret.append(str(item.address))

    return ret


def resolve(name, rdtype, server):      # takes the name of the website, rdtype (i.e: 'A', 'NS', 'MX')
    try:
        qname = dns.name.from_text(str(name))
        query = dns.message.make_query(qname, rdtype)
        response = dns.query.udp(query, server, 2.0)
    except:
        return None

    # print('qname: ', qname, ' server: ', server)

    if response.rcode() == dns.rcode.NOERROR:    # Checking if there is any error occured
        answer = response.answer
        ret = []
        cname_list = []
        #   Now If we have the answer section, it means we have found the nameserver and the answer section
        #           contains the ip address of that website
        if len(answer) != 0:
            for ans in answer:
                #   If there is multiple address of multiple ip's then we should return all of them
                ret += get_result(ans.items, ANSWER, rdtype)
                #   In some cases the server we are in that doesn't have the actual IP address of NS/MX records
                #           but contains the canonical name.
                #           In this situation we should start quering again from the root server with that
                #           canonical names.
                cname_list += get_result(ans.items, ANSWER, query_type('CNAME'))

            if len(ret) != 0:
                #   It seems we have the desired result. So now we can just return the result list.
                return ret

            # Now if we have Canonical name but we do not require the IP address we can return the list
            if len(cname_list) != 0:
                if rdtype == query_type('NS') or rdtype == query_type('MX'):
                    return cname_list

        #   Since we do not have the desired output in this server, we will need to look further.
        #       1. We can use the canonical name and start from the root-servers angain
        #       2. We can get the IP address from the additional section and use it as next server
        #       3. If we do not have anything in additional section we won't be able to get any IP address.
        #           In this case, for tcp query, we can take the NS address from the authority section and
        #           start from the root server for the address. So we will start looking for A record
        #           for retrieving the IP address.
        name_list = []
        servers = []
        changed = False
        if len(cname_list) != 0:
            name_list += cname_list
            servers += root_server_ip
        elif len(response.additional) != 0:
            name_list.append(str(qname))
            for i in range(len(response.additional)): #iterating rrset
                servers += get_result(response.additional[i].items, ADDITIONAL, None)
        else:
            changed = True
            for i in range(len(response.authority)):
                name_list += get_result(response.authority[i].items, AUTHORITY, None)
            # print("hello here")
            # if rdtype == query_type('NS'):
            #     return name_list
            servers += root_server_ip

        for server in servers:
            for name in name_list:
                if changed:
                    ret = resolve(name, query_type('A'), server)
                else:
                    ret = resolve(name, rdtype, server)
                if ret is not None:
                    if changed:
                        ret = resolve(qname, rdtype, ret[0])
                    return ret

    return None


def main(argv):
    #   Input Processing
    s_query = argv[0]       # website url
    s_query_type = argv[1]  # query type: “A”, “NS”, “MX”

    qtype = query_type(s_query_type)
    for server in root_server_ip:
        ret = resolve(s_query, qtype, server)
        if ret is not None:
            print(ret)
            break


if __name__ == "__main__":
    main(sys.argv[1:])

#########################################
#              Zafar Ahmad              #
#           SBU ID: 111195037           #
#        Implementation: mydig-dnssec   #
#########################################

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

#   Returns the KSK from the section (answer or authority) containing the DNSKEY
def get_ksk(section_list):
    for section in section_list:
        for item in section.items:
            if item.flags == 257:   #KSK
                return item
    return None


#   Returns the DS from the section (answer or authority) containing the DS
def get_ds(section_list):
    for section in section_list:
        for item in section.items:
            if item.rdtype == 43:   # DS
                return item
    return None


#   Returns the name which is available with each item name in authority, answer etc.
def get_current_name(section_list):
    for section in section_list:
        return section.name


#   Returns the Algorithm name based on the digest type of DS value
def get_algorithm_for_digest(digest_type):
    if digest_type == 1:
        return 'SHA1'
    if digest_type == 2:
        return 'SHA256'
    if digest_type == 4:
        return 'SHA384'
    return None


def resolve(name, rdtype, server):      # takes the name of the website, rdtype (i.e: 'A', 'NS', 'MX')
    try:
        qname = dns.name.from_text(str(name))
        query = dns.message.make_query(qname, rdtype)
        response = dns.query.udp(query, server, 2.0)
    except:
        return None

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
                #######################  DNS-SEC  #########################
                #   In DNS-SEC we have DNSKEY, RRset, RRSIG, DS
                #   In each step we are suppose to verify the Keys and RRset
                #   For verifiying we have ZSK and KSK

                #   Prepare the query for fetching the RRset.
                q = dns.message.make_query(qname, dns.rdatatype.A, want_dnssec=True)
                #   Prepare the query for fetching the DNSKEY
                q_sec = dns.message.make_query(qname, dns.rdatatype.DNSKEY, want_dnssec=True)
                r = dns.query.tcp(q, server, timeout=5)            # r response will contain the RRset, RRSIG of RRset
                r_sec = dns.query.tcp(q_sec, server, timeout=5)    # r_res response will contain the DNSKEY (ZSK, KSK), RRSIG or DNSKEY

                a = r.answer
                a_sec = r_sec.answer
                if len(a) == 0 or len(a_sec) == 0:      # now if their answer section is empty it means that server
                    print('DNSSEC not supported')       #                             doesn't support the DNSSEC
                    return 'failed'

                #   Validate the RRset and DNSKEY
                try:
                    dns.dnssec.validate(a[0], a[1], {qname: a_sec[0]})              # Validate the RRset
                    dns.dnssec.validate(a_sec[0], a_sec[1], {qname: a_sec[0]})      # Validate the DNSKEY
                except:
                    print('DNSSec verification failed')
                    return 'failed'
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
            for i in range(len(response.additional)):
                servers += get_result(response.additional[i].items, ADDITIONAL, None)
        else:
            changed = True
            for i in range(len(response.authority)):
                name_list += get_result(response.authority[i].items, AUTHORITY, None)
            if rdtype == query_type('NS'):
                return name_list
            servers += root_server_ip

        for next_server in servers:
            for next_name in name_list:
                if changed:
                    ret = resolve(next_name, query_type('A'), next_server)
                else:
                    #   We know how to verify both the RRset and DNSKey. But if both the ZSK and KSK is compromised,
                    #   what to do? That's why we will have to implement the CHAIN OF TRUST (aka: DS validation).
                    #   In this can we will recursively verify the childs hashed KSK with the DS this servers DS digest
                    #   value.

                    current_name = str(get_current_name(response.authority))
                    rrset_query = dns.message.make_query(current_name, dns.rdatatype.A, want_dnssec=True)
                    ds_query = dns.message.make_query(current_name, dns.rdatatype.DS, want_dnssec=True)
                    dnskey_query_child = dns.message.make_query(current_name, dns.rdatatype.DNSKEY, want_dnssec=True)

                    rrset_response = dns.query.tcp(rrset_query, server, timeout=5)
                    ds_response = dns.query.tcp(ds_query, server, timeout=5)
                    dnskey_response_child = dns.query.tcp(dnskey_query_child, next_server, timeout=5)

                    #   Get the stored DS value in this server
                    ds = get_ds(ds_response.answer)
                    #   Get the KSK of child server
                    child_ksk = get_ksk(dnskey_response_child.answer)

                    #   If any of the values doesnt exist, it means these server doesn't support the DNS-SEC
                    if (ds is not None) and (child_ksk is not None):
                        #   Parse the algorithm value which was used to encrypt the DS
                        algorithm = get_algorithm_for_digest(ds.digest_type)
                        #   Generate the DS value using the child's KSK and required algorithm
                        child_ds = dns.dnssec.make_ds(dns.name.from_text(current_name), child_ksk, algorithm)
                        if ds.digest == child_ds.digest:    # Match the the digest values of both of them
                            try:
                                #   Validating the Keys in this level
                                dns.dnssec.validate(dnskey_response_child.answer[0], dnskey_response_child.answer[1],
                                                    {dns.name.from_text(current_name): dnskey_response_child.answer[0]})
                            except:
                                print('DNSSec verification failed')
                                return "failed"
                        else:
                            print('DNSSec verification failed')
                            return "failed"
                    else:
                        print('DNSSEC not supported')
                        return "failed"

                    #   If the DNS-SEC verification of this level is successful, then go for the next level.
                    ret = resolve(next_name, rdtype, next_server)
                if ret is not None:
                    if changed and ret != 'failed':
                        ret = resolve(qname, rdtype, ret[0])
                    return ret
    return None


def main(argv):
    #   Input Processing
    s_query = argv[0]       # website url
    for server in root_server_ip:
        ret = resolve(s_query, dns.rdatatype.A, server)
        if ret is not None:
            if ret != 'failed':
                print(ret)
            break


if __name__ == "__main__":
    main(sys.argv[1:])

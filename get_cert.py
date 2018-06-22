#!/usr/bin/evn python2.7
# -*- coding: utf-8 -*-
"""
获取证书信息

"""
import ssl
import socket
import urlparse

from lib.utils import time_limit


def get_certificate_dev(domain):
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.socket(), server_hostname=domain)
    try:
        s.connect((domain, 443))
        cert = s.getpeercert()
        return cert
    except ssl.CertificateError as e:
        print str(e)
        return 0
    except ssl.SSLError as e:
        print str(e)
        return 1
    except Exception as e:
        print str(e)
        return -1


@time_limit(5)
def get_certificate(domain, index):
    if index % 1 == 0:
        print "step:%d" % index

    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.socket(), server_hostname=domain)
    try:
        s.connect((domain, 443))
        cert = s.getpeercert()
        return cert
    except ssl.CertificateError:
        return 0
    except ssl.SSLError:
        return 1
    except:
        return -1


def get_certificate_list(urls):
    domains = list(set([urlparse.urlparse(_).hostname for _ in urls]))
    print len(domains)
    res_dict = dict()
    for index, domain in enumerate(domains):
        try:
            cert = get_certificate(domain, index)
            res_dict[domain] = cert
        except:
            pass
    return res_dict

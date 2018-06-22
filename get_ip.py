#!/usr/bin/evn python2.7
# -*- coding: utf-8 -*-
"""
特征抽取
"""
import socket
import urlparse
from collections import defaultdict

from joblib import Parallel, delayed

from logger import logger

N_JOBS = 4


def _core_get_ip(url):
    """
    :param url:
    :return:
    """
    try:
        domain = urlparse.urlparse(url).hostname
        ip = socket.gethostbyname(domain)
    except Exception as e:
        logger.warning("%s ip request failed %s" % (url, str(e)))
        ip = "unknown"
    return ip, url

def _core_get_dip(domain):
    """
    :param url:
    :return:
    """
    try:
        dip = socket.gethostbyname_ex(domain)
    except Exception as e:
        logger.warning("%s ip request failed %s" % (domain, str(e)))
        dip = None
    return dip, domain


def make_url_ip_map(urls, n_jobs=N_JOBS):
    res = Parallel(n_jobs=n_jobs)(delayed(_core_get_ip)(url) for url in urls)
    url_ip_map = dict()
    for ip, url in res:
        url_ip_map[url] = ip
    return url_ip_map


def make_url_ip_dmap(urls, n_jobs=N_JOBS):
    domains = [urlparse.urlparse(_).hostname for _ in urls]
    res = Parallel(n_jobs=n_jobs)(delayed(_core_get_dip)(domain) for domain in domains)
    url_ip_dmap = dict()
    for dip, domain in res:
        if dip:
            url_ip_dmap[domain] = dip
    return url_ip_dmap


def make_ip_url_map(urls, n_jobs=N_JOBS):
    res = Parallel(n_jobs=n_jobs)(delayed(_core_get_ip)(url) for url in urls)
    ip_url_map = defaultdict(list)
    for ip, url in res:
        ip_url_map[ip].append(url)
    return ip_url_map

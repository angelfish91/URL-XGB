#!/usr/bin/evn python2.7
# -*- coding: utf-8 -*-
"""
利用maltrail的可疑顶级域名

"""
import urlparse


def extract_sus_url(urls, filepath="../refference/maltrail/trails/static/suspicious/domain.txt"):
    """
    获取可疑的url
    :param urls:
    :return:
    """
    with open(filepath, 'r') as f:
        sus_suffix = [_.strip() for _ in f]
        sus_suffix = [_ for _ in sus_suffix if not _.startswith('#') and len(_) > 1]

    sus_domain = set()
    domains = list(set([urlparse.urlparse(_).hostname for _ in urls]))
    print "domain cnt:%d" %len(domains)
    for index, domain in enumerate(domains):
        for _ in sus_suffix:
            if domain.endswith(_):
                sus_domain.add(domain)
    return sus_domain
#!/usr/bin/evn python2.7
# -*- coding: utf-8 -*-
"""
当前获取网站域名的page rank

"""
import re
import time
import urlparse

from lib.utils import get_url


def get_pr(domain):
    """
    获取域名pagerank
    :param domain:
    :return:
    """
    search_url = 'https://pr.aizhan.com/' + domain + "/"
    html = ""
    try:
        html, url_code, real_url = get_url(search_url)
    except:
        pass
    pattern = 'statics\.aizhan\.com/images/pr/(\d)\.png'
    pattern = re.compile(pattern)
    pr = pattern.findall(html)
    return pr


def get_pr_list(urls, pr_dict = None):
    """
    获取一批url的pagerank
    :param urls:
    :return:
    """
    if pr_dict is None:
        domain_pr_map = dict()
    else:
        domain_pr_map = pr_dict
    domains = list(set([urlparse.urlparse(url).hostname for url in urls]))
    for domain in domains:
        if domain in pr_dict:
            continue
        time.sleep(1)
        domain_pr_map[domain] = get_pr(domain)
    return domain_pr_map
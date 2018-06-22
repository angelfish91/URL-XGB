#!/usr/bin/evn python2.7
# -*- coding: utf-8 -*-
"""
当前获取网站域名的alexa rank

"""
import time
import urlparse

import seolib
from joblib import Parallel, delayed

from logger import logger


def get_scheme_domain(url):
    hostname = urlparse.urlparse(url).hostname
    scheme_domain = "".join(["http://", hostname])
    return scheme_domain


def get_alexa_rank(url, index):
    if index % 1000 == 0:
        logger.info("step:%d" % index)
    rank = -1
    for i in range(10):
        try:
            rank = seolib.get_alexa(url)
        except Exception as e:
            if i >= 9:
                logger.error("get alexa info error %s %s" % (url, str(e)))
                break
            else:
                time.sleep(1)
        else:
            break
    return rank


def get_alexa_rank_list(urls, n_jobs=8):
    scheme_domains = list(set([get_scheme_domain(_) for _ in urls]))
    logger.info("scheme domains count:%d" % (len(scheme_domains)))
    res_list = Parallel(n_jobs=n_jobs)(
        delayed(get_alexa_rank)(url, index) for index, url in enumerate(scheme_domains))
    res_dict = dict()
    for index, res in enumerate(res_list):
        res_dict[scheme_domains[index]] = res
    return res_dict

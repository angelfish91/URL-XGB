#!/usr/bin/evn python2.7
# -*- coding: utf-8 -*-
"""
whois 信息抽取

"""
import os
import time
import urlparse
import datetime

import whois
import tldextract
import joblib as jl
from joblib import Parallel, delayed

from logger import logger


def get_primary_domain(url):
    hostname = urlparse.urlparse(url).hostname
    tld_obj = tldextract.extract(hostname)
    domain = tld_obj.domain
    suffix = tld_obj.suffix
    return ".".join([domain, suffix])


def get_whois(url, output_path, index, check):
    # log index for multi-process
    if index % 1000 == 0:
        logger.info("step:%d" % index)
    file_path = os.path.join(output_path, url + ".jl.z")
    # check whether it is download
    if check and os.path.isfile(file_path):
        return jl.load(file_path)
    # try to download the whois info
    for i in range(10):
        try:
            whois_info = whois.whois(url)
        except Exception as e:
            if i >= 9:
                logger.error("get whois info error %s %s" % (url, str(e)))
                break
            else:
                time.sleep(1)
        else:
            break
    whois_text = ""
    # tye to dump the whois info
    try:
        whois_text = whois_info.text
    except:
        pass
    if whois_text and output_path is not None:
        jl.dump(whois_text, file_path)
    return whois_text


def get_whois_list(urls, output_path=None, check=True, n_jobs=32):
    """
    get whois info
    """
    primary_domain = list(set([get_primary_domain(_) for _ in urls]))
    logger.info("primary_domain count:%d" % len(primary_domain))
    res_list = Parallel(n_jobs=n_jobs)(
        delayed(get_whois)(url, output_path, index, check) for index, url in enumerate(primary_domain))
    res_dict = dict()
    for index, res in enumerate(res_list):
        res_dict[primary_domain[index]] = whois.WhoisEntry.load(primary_domain[index], res)
    return res_dict


def load_whois_dict(path):
    filename_list = os.listdir(path)
    res_dict = dict()
    for filename in filename_list:
        text = jl.load(os.path.join(path, filename))
        primary_domain = filename[:-5]
        res_dict[primary_domain] = whois.WhoisEntry.load(primary_domain, text)
    return res_dict


def get_url_whois_dict(url, whois_dict):
    primary_domain = get_primary_domain(url)
    if primary_domain in whois_dict:
        return whois_dict[primary_domain]
    else:
        return whois.WhoisEntry.load(primary_domain, "")


class extract_feature_whois:
    def __init__(self, url, whois_dict):
        self.url = url
        self.url_whois = get_url_whois_dict(url, whois_dict)
        self.now = datetime.datetime.now()
        self.parse_whois_info()

    def parse_whois_info(self):
        self.exp_date = self.url_whois.get('expiration_date', 0)
        self.reg_date = self.url_whois.get('creation_date', 0)
        self.update_date = self.url_whois.get('updated_date', 0)
        if isinstance(self.exp_date, list):
            self.exp_date = self.exp_date[0]
        if isinstance(self.reg_date, list):
            self.reg_date = self.reg_date[0]
        self.registrar = self.url_whois.get('registrar', "")

    def get_timedelta(self):
        res = None
        try:
            res = (self.exp_date - self.reg_date).days / 365.
        except Exception as e:
            pass
        return res

    def get_update_timedelta(self):
        res = None
        try:
            res = (self.now - self.update_date).days / 365.
        except Exception as e:
            pass
        return res

    def get_exp_timedelta(self):
        res = None
        try:
            res = (self.exp_date - self.now).days / 365.
        except Exception as e:
            pass
        return res

    def get_reg_timedelta(self):
        res = None
        try:
            res = (self.now - self.reg_date).days / 365.
        except Exception as e:
            pass
        return res

    def get_registrar(self):
        return self.registrar


def get_whois_feature(urls, whois_dict):
    res1, res2, res3, res4, res5 = [], [], [], [], []
    for url in urls:
        ext_obj = extract_feature_whois(url, whois_dict)
        res1.append(ext_obj.get_timedelta())
        res2.append(ext_obj.get_exp_timedelta())
        res3.append(ext_obj.get_reg_timedelta())
        res4.append(ext_obj.get_update_timedelta())
        res5.append(ext_obj.get_registrar())
    return res1, res2, res3, res4, res5





#!/usr/bin/evn python2.7
# -*- coding: utf-8 -*-
"""
特征抽取
"""
import urlparse
import tldextract
from collections import defaultdict

from get_lexical import url_lexical_batch

PRIMARY_DOMAIN_CNT = 5
SUB_DOMAIN_CNT = 10
TOTAL_DOMAIN_CNT = 10


class FeatureExtract(object):
    """
    特征抽取
    """
    def __init__(self, mal_urls, ben_urls):
        self.mal_urls = mal_urls
        self.ben_urls = ben_urls
        self.mal_filename = set()
        self.ben_filename = set()
        self.mal_filepath = set()
        self.ben_filepath = set()
        self.mal_pdomain_tokens = set()
        self.mal_sdomain_tokens = set()
        self.ben_pdomain_tokens = set()
        self.ben_sdomain_tokens = set()
        self.mal_ips = set()
        self.domain_path_map = defaultdict(set)
        self.domain_port_map = defaultdict(set)

    def domain_path_structure_analyze(self, urls):
        """
        url路径统计
        :param urls:
        :return:
        """
        for url in urls:
            url_obj = urlparse.urlparse(url)
            domain = url_obj.hostname
            path = url_obj.path
            if '.' in path.split('/')[-1]:
                self.domain_path_map[domain].add(path.rsplit('/', 1)[0])
            else:
                self.domain_path_map[domain].add(path)

    def domain_port_analyze(self, urls):
        """
        构建domain port map字典
        :param urls:
        :return:
        """
        for url in urls:
            netloc = urlparse.urlparse(url).netloc
            domain = urlparse.urlparse(url).hostname
            tld_obj = tldextract.extract(domain)
            domain = ".".join([tld_obj.domain, tld_obj.suffix])
            if netloc.count(":") > 0:
                self.domain_port_map[domain].add(netloc.rsplit(":")[-1])

    def get_malip(self, urls, url_ip_dmap, primary_domain_cnt=PRIMARY_DOMAIN_CNT, sub_domain_cnt=SUB_DOMAIN_CNT,
                  total_domain_cnt=TOTAL_DOMAIN_CNT):
        """
        抽取恶意ip地址
        :param urls:
        :param url_ip_dmap:
        :param primary_domain_cnt:
        :param sub_domain_cnt:
        :param total_domain_cnt:
        :return:
        """
        malip_map = defaultdict(list)
        for url in urls:
            domain = urlparse.urlparse(url).hostname
            if domain in url_ip_dmap:
                for ip in url_ip_dmap[domain][2]:
                    malip_map[ip].append(url)

        for ip in malip_map:
            if ip.count(".") == 3:
                primary_domains, sub_domains = set(), set()
                for url in malip_map[ip]:
                    domain = urlparse.urlparse(url).hostname
                    primary_domains.add(tldextract.extract(domain).domain)
                    sub_domains.add(tldextract.extract(domain).subdomain)
                if (len(primary_domains) >= primary_domain_cnt or len(sub_domains) >= sub_domain_cnt) \
                        and len(malip_map[ip]) >= total_domain_cnt:
                    self.mal_ips.add(ip.rsplit(".", 1)[0])

    def feature_extract(self, url_ip_dmap):
        """
        抽取词汇特征
        :return:
        """
        mal_filename, mal_filepath, mal_pdomain_token, mal_sdomain_token = url_lexical_batch(self.mal_urls)
        ben_filename, ben_filepath, ben_pdomain_token, ben_sdomain_token = url_lexical_batch(self.ben_urls)

        self.mal_pdomain_tokens = mal_pdomain_token - ben_pdomain_token
        self.mal_sdomain_tokens = mal_sdomain_token - ben_sdomain_token

        self.ben_pdomain_tokens = ben_pdomain_token - mal_pdomain_token
        self.ben_sdomain_tokens = ben_sdomain_token - mal_sdomain_token

        self.mal_filepath = mal_filepath - ben_filepath
        self.ben_filepath = ben_filepath - mal_filepath

        self.mal_filename = mal_filename - ben_filename
        self.ben_filename = ben_filename - mal_filename

        self.domain_path_structure_analyze(set(self.mal_urls) | set(self.ben_urls))
        self.domain_port_analyze(set(self.mal_urls) | set(self.ben_urls))

        self.get_malip(self.mal_urls, url_ip_dmap)



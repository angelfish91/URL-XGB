#!/usr/bin/evn python2.7
# -*- coding: utf-8 -*-
"""
特征向量制作

"""
import tldextract
import numpy as np

from get_lexical import UrlLexical
from get_whois import extract_feature_whois
from get_rank import get_scheme_domain


class build_feature(object):
    def __init__(self, data_obj, url_ip_map, url_ip_dmap, pdomain_whois_map, domain_rank_map, domain_cert_map, \
                 domain_pr_map, sus_domain):
        self.data_obj = data_obj
        self.url_ip_map = url_ip_map
        self.url_ip_dmap = url_ip_dmap
        self.pdomain_whois_map = pdomain_whois_map
        self.domain_rank_map = domain_rank_map
        self.domain_cert_map = domain_cert_map
        self.domain_pr_map = domain_pr_map
        self.sus_domain = sus_domain

    def __getkey(self, url):
        # 获取词汇特征
        lex_obj = UrlLexical(url)
        filename, filepath, pdomain_token, sdomain_token = lex_obj.do_extract()

        # 获取rank
        scheme_domain = get_scheme_domain(url)
        rank = self.domain_rank_map.get(scheme_domain, None)

        # 获取whois信息
        whois_obj = extract_feature_whois(url, self.pdomain_whois_map)
        exp_timedelta = whois_obj.get_exp_timedelta()
        reg_timedelta = whois_obj.get_reg_timedelta()
        upd_timedelta = whois_obj.get_update_timedelta()
        timedelta = whois_obj.get_timedelta()
        registrar = whois_obj.get_registrar()

        # 获取pdomain
        tld_obj = tldextract.extract(lex_obj.url_domain)
        url_pdomain = ".".join([tld_obj.domain, tld_obj.suffix])
        url_domain = lex_obj.url_domain
        url_path = lex_obj.url_path
        url_netloc = lex_obj.url_netloc

        return filename, filepath, pdomain_token, sdomain_token, rank, exp_timedelta, reg_timedelta, upd_timedelta,\
            timedelta, registrar, url_pdomain, url_domain, url_path, url_netloc

    def build_feature(self, url):
        """
        :param url:
        :return:
        """
        filename, filepath, pdomain_token, sdomain_token, rank, exp_timedelta, reg_timedelta, upd_timedelta,\
            timedelta, registrar, url_pdomain, url_domain, url_path, url_netloc = self.__getkey(url)

        feature = np.zeros((1, 30), dtype=np.float32)

        # feature 1: domain path length
        if url_domain in self.data_obj.domain_path_map:
            feature[0][0] = len(self.data_obj.domain_path_map[url_domain])
            
        # feature 2: filename
        if filename and filename in self.data_obj.mal_filename:
            feature[0][1] = 1
            
#         if filename and filename in self.data_obj.ben_filename:
#             feature[0][2] = 1

        # feature 3: filepath
        if filepath and filepath in self.data_obj.mal_filepath:
            feature[0][3] = 1
        
#         if filename and filename in self.data_obj.ben_filepath:
#             feature[0][4] = 1

        # feature 4: domain tokens
        for token in pdomain_token:
            if token in self.data_obj.mal_pdomain_tokens:
                feature[0][5] = 1
            if token in self.data_obj.ben_pdomain_tokens:
                feature[0][7] = 1

        for token in sdomain_token:
            if token in self.data_obj.mal_sdomain_tokens:
                feature[0][6] = 1
            if token in self.data_obj.ben_sdomain_tokens:
                feature[0][8] = 1

        # feature 5: ip
        if url in self.url_ip_map and self.url_ip_map[url].rsplit(".", 1)[0] in self.data_obj.mal_ips:
            feature[0][9] += 1

        # feature 6: regisration time
        if reg_timedelta is not None:
            feature[0][10] = reg_timedelta

        # feature 7 reg exp time
        if timedelta is not None:
            feature[0][11] = timedelta

        # feature 8: update time
        if upd_timedelta is not None:
            feature[0][12] = upd_timedelta

        # feature 9 rank:
        if rank is None or rank > 10000000:
            feature[0][13] = 1

        if rank is not None and rank < 100000:
            feature[0][14] = 1

        # feature 10 cert:
        if url_domain in self.domain_cert_map and not isinstance(self.domain_cert_map[url_domain], int):
            feature[0][15] = 1

        # feature 11 maltrail:
        if url_domain in self.sus_domain:
            feature[0][16] = 1

        # feature 12 port num
        if url_pdomain in self.data_obj.domain_port_map:
            feature[0][17] = len(self.data_obj.domain_port_map[url_pdomain])

        # feature 15-17 filename lexical
        if filename and filename.count("%") / float(len(filename)) > 0.2 and filename[-3:] == "exe":
            feature[0][18] = 1

        if filename and filename.count("@") > 0:
            feature[0][19] = 1

        # feature 19 path level count
        if url_path:
            feature[0][20] = url_path.count("/")

        # feature 20-21
        if url_domain in self.url_ip_dmap:
            feature[0][21] = len(self.url_ip_dmap[url_domain][1])
            feature[0][22] = len(self.url_ip_dmap[url_domain][2])

        if url_domain:
            for char in url_domain:
                if char.isdigit():
                    feature[0][23] += 1

            feature[0][24] = len(url_domain) / url_domain.count(".")
            feature[0][25] = max([len(_) for _ in url_domain.split(".")])

        # feature 22 name servers count
        if url_pdomain in self.pdomain_whois_map and 'name_servers' in self.pdomain_whois_map and \
                self.pdomain_whois_map[url_pdomain]['name_servers']:
            feature[0][26] = len(self.pdomain_whois_map[url_pdomain]['name_servers'])

        if url_pdomain in self.pdomain_whois_map and 'status' in self.pdomain_whois_map and \
                self.pdomain_whois_map[url_pdomain]['status']:
            feature[0][27] = len(self.pdomain_whois_map[url_pdomain]['status'])

        if url_domain in self.domain_pr_map and self.domain_pr_map[url_domain] > 0:
            feature[0][28] = 1

#         deep digger into geo info

#             if domain in url_ip_dmap:
#                 asn_set = set()
#                 ips = url_ip_dmap[domain][2]
#                 for ip in ips:
#                     asn_set.add(asndb.asn_by_addr(ip))
#                 feature[0][25] = len(asn_set)

#             if domain in url_ip_dmap:
#                 geo_set = set()
#                 ips = url_ip_dmap[domain][2]
#                 for ip in ips:
#                     if citydb.record_by_name(ip):
#                             geo_set.add(citydb.record_by_name(ip)['city'])
#                 feature[0][26] = len(geo_set)

#         feature filename

#         if filename:
#             feature[0][29] = filename.count("_")

#         feature whois emails

#             if pdomain in whois_dict and 'emails' in whois_dict and whois_dict[pdomain]['emails']:
#                  feature[0][23] = len(whois_dict[pdomain]['emails'])

#         feature whois country

#             if pdomain in whois_dict and 'country' in whois_dict and whois_dict[pdomain]['country']!="CN":
#                 feature[0][23] = 1

#         feature registrar

#             vector_obj = HashingVectorizer(n_features=64)
#             if registrar:
#                 ff_add = vector_obj.fit_transform([registrar]).toarray()
#             else:
#                 ff_add = np.zeros((1, 64), dtype = np.float32)
#             feature = np.concatenate((feature, ff_add), axis = 1)

#         feature asn ratio

#             if url in url_ip_map and  url_ip_map[url] !='unknown':
#                 asn = asndb.lookup(url_ip_map[url])[0]
#                 if asn is not None and asn in asn_score_map:
#                     feature[0][22] = asn_score_map[asn]

        return feature


    def build_feature_set(self, urls):
        feature = []
        for url in urls:
            feature.append(self.build_feature(url))
        feature = np.concatenate(feature, axis=0)
        return feature
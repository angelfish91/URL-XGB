#!/usr/bin/evn python2.7
# -*- coding: utf-8 -*-
"""
当前获取网站域名的DNS信息

"""
import logging

import json
import requests

from lib.utils import check_domain
from lib.domain_ana import DomainSuffix


dns_servers = [{'id':14459302,'ip':"lkun8RYau8UDOnT7Ctg8Ww=="},
               {'id':14459314,'ip':"pc5LXpA6Y0LtmOpoKX3zGA=="},
               {'id':14459315,'ip':"pc5LXpA6Y0LtmOpoKX3zGA=="},
               {'id':14459318,'ip':"Rv90/Ksj1L5uT4T9vkFqHw=="},
               {'id':14459319,'ip':"Rv90/Ksj1L6zXUx96XEFbA=="},
               {'id':14459324,'ip':"17cLkr6FDgVDhWGNIzx4Jg=="},
               {'id':14459326,'ip':"wfe/baph0aVy7vSzQ8JCew=="},
               {'id':14459327,'ip':"DiRV3R7jjMVfu0/d6bXYTg=="},
               {'id':14459329,'ip':"wfe/baph0aVy7vSzQ8JCew=="},
               {'id':14459330,'ip':"5KYA0MQ8FeqHPEqrt|1wpg=="},
               {'id':14459331,'ip':"Tllr7HLQodVpDDFM0Ssc9A=="},
               {'id':14459328,'ip':"Tllr7HLQodVpDDFM0Ssc9A=="},
               {'id':14459303,'ip':"zFjFw1wXjPGw24s1pgwUlg=="},
               {'id':14459306,'ip':"zFjFw1wXjPGw24s1pgwUlg=="},
               {'id':14459307,'ip':"jPGdz69k/dfq28vDX6i31Q=="},
               {'id':14459300,'ip':"UAkij/Offsua9LBVAMvIWA=="},
               {'id':14459301,'ip':"qTi6Juz6ZcZq9u5nbt9bwg=="},
               {'id':14459311,'ip':"8GyD8H1tV0bLcSJd3blMWA=="},
               {'id':14459312,'ip':"lsB7oELLLoiNHPwhyWj4YA=="},
               {'id':14459313,'ip':"xR0BFfdbQfPoiJapBMevOA=="},
               {'id':14459325,'ip':"/GyDof5h2t9ienVd9pEK4g=="},
               {'id':14459320,'ip':"coLNT8qlpx2N8iBO8na1Rw=="},
               {'id':14459321,'ip':"smuXAjaliTJ7UQSs9Ne65A=="},
               {'id':14459322,'ip':"VZWE4uxPBJAKFLPTtoHyyQ=="},
               {'id':14459323,'ip':"VZWE4uxPBJAKFLPTtoHyyQ=="},
               {'id':14459299,'ip':"4|LMEILycPoa9DPxVJb3gg=="},
               {'id':14459316,'ip':"abaieVMlEG3aU4jEmZOZrg=="},
               {'id':14459317,'ip':"abaieVMlEG3aU4jEmZOZrg=="},
               {'id':14459308,'ip':"vhRBox4HOXDg7vqwXXP3hw=="},
               {'id':14459309,'ip':"FUFXcwK4d|5goTcqAeJyHA=="},
               {'id':14459310,'ip':"FUFXcwK4d|6ZedmSL5d4Lw=="},
               {'id':14459304,'ip':"4|LMEILycPoa9DPxVJb3gg=="},
               {'id':14459305,'ip':"/LqwY7|RTOTUAm/8Eln8dQ=="}]

class DNSInfoParser:
    """解析chinaz和beianbeian网页，获取对应的ICP信息"""
    def __init__(self, domain):
        """
        :param domain:
        """
        self.__domain = domain
        self.__domian_suffix_obj = DomainSuffix()
        self.__all_domians_suffix = self.__domian_suffix_obj.get_all_domain_suffix()

    def get_top_domian(self):
        """
        获取域名中的主域名
        :return:
        """
        index = 0
        domain_list = self.__domain.split(".")
        for i, suffix in enumerate(reversed(domain_list)):
            if suffix not in self.__all_domians_suffix:
                index = i
                break

        if index == 0:
            index = 1

        top_domain = '.'.join(domain_list[-(index + 1):])
        return top_domain

    def parse_dns_chinaz_html(self, top_domain):
        """

        :param top_domain:
        :return:
        """
        ttl_list = []
        post_data = {'host':top_domain,'type':1,'total':1,'process':0,'right':0}
        for i in range(len(dns_servers)):
            try:
                url = "http://tool.chinaz.com/AjaxSeo.aspx?t=dns&server=" + dns_servers[i]["ip"] + \
                      "&id=" + str(dns_servers[i]['id'])
                res = requests.post(url, data=post_data)
                res = res.text
                res = json.loads(res[1:-1])
            except Exception, e:
                logging.warning("parse chinaz dns server %s wrong: %s" % (dns_servers[i]["ip"],str(e)))
                continue
            try:
                ttl_list.append(int(res['list'][0]['ttl']))
            except:
                pass
        return ttl_list

    def do_get_dns_info(self):
        """
        :return:
        """
        # 先判断域名是否是合法的
        if not check_domain(self.__domain):
            raise ValueError("this domain is not legal")

        top_domain = self.get_top_domian()

        ttl_list = []
        try:
            ttl_list = self.parse_dns_chinaz_html(top_domain)
        except Exception as e:
            logging.warn("get chinaz dns info is wrong: %s" % str(e))
        return ttl_list
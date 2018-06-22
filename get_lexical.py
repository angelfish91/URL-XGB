#!/usr/bin/evn python2.7
# -*- coding: utf-8 -*-
"""
特征抽取

"""
from collections import Counter

import urlparse
import tldextract

# 文件名长度
FILE_NAME_LEN_THRESH = 10
# URL路径深度
URL_PATH_DEPTH_THRESH = 3
URL_PATH_LEN_THRESH = 4
# 域名token频数限制
TOKEN_FQ_THRESH = 3


class UrlLexical(object):
    """
    抽取URL词汇特征
    """
    def __init__(self, url):
        """
        抽取词汇特征
        :param url:
        """
        self.url_obj = urlparse.urlparse(url)
        self.url_path = self.url_obj.path
        self.url_domain = self.url_obj.hostname
        self.url_netloc = self.url_obj.netloc

        self.filename = self.get_filename(FILE_NAME_LEN_THRESH)
        self.filepath = self.get_filepath(URL_PATH_LEN_THRESH)
        self.pdomain_token, self.sdomain_token = self.get_domain_token()

    def get_filename(self, len_thresh):
        """
        抽取文件名
        :param len_thresh:
        :return:
        """
        lastpath = self.url_path.rsplit('/')[-1]
        if lastpath.count('.') >= 1 and len(lastpath) > len_thresh:
            return lastpath
        return ""

    def get_filepath(self, len_thresh):
        """
        获取文件路径
        :param len_thresh:
        :return:
        """
        if len(self.url_path.rsplit('/')) >= URL_PATH_DEPTH_THRESH:
            filepath = '/'.join(self.url_path.rsplit('/')[-1*URL_PATH_DEPTH_THRESH:-1])
            if len(filepath) > len_thresh:
                return filepath
        return ""

    def get_domain_token(self):
        """
        抽取主域名与子域名token
        :return:
        """
        pdomain = tldextract.extract(self.url_domain).domain
        sdomain = tldextract.extract(self.url_domain).subdomain
        pdomain_token = [_ for _ in pdomain.split(".") if not _.isdigit() and len(_) > 1]
        sdomain_token = [_ for _ in sdomain.split(".") if not _.isdigit() and len(_) > 1]
        return pdomain_token, sdomain_token

    def do_extract(self):
        """
        抽取URL词汇特征
        :return:
        """
        return self.filename, self.filepath, self.pdomain_token, self.sdomain_token


def url_lexical_batch(urls):
    """
    批量抽取URL词汇特征
    :param urls:
    :return:
    """
    filename_list, filepath_list, pdomain_token_list, sdomain_token_list = list(), list(), list(), list()
    for url in urls:
        lex_obj = UrlLexical(url)
        filename, filepath, pdomain_token, sdomain_token = lex_obj.do_extract()
        filename_list.append(filename)
        filepath_list.append(filepath)
        pdomain_token_list.extend(pdomain_token)
        sdomain_token_list.extend(sdomain_token)

    filename_list = set([_ for _ in filename_list if _])
    filepath_list = set([_ for _ in filepath_list if _])
    pdomain_token_list = [_ for _ in pdomain_token_list if _]
    sdomain_token_list = [_ for _ in sdomain_token_list if _]

    pdomain_cnt_dict = Counter(pdomain_token_list)
    sdomain_cnt_dict = Counter(sdomain_token_list)
    pdomain_token_list = set([k for k, v in pdomain_cnt_dict.items() if v >= TOKEN_FQ_THRESH])
    sdomain_token_list = set([k for k, v in sdomain_cnt_dict.items() if v >= TOKEN_FQ_THRESH])

    return filename_list, filepath_list, pdomain_token_list, sdomain_token_list

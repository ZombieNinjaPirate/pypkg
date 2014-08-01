"""The functions included in this module can be called to extract different types of adderss objects
such as IP, URL and email addresses. """


"""
Copyright (c) 2014, Are Hansen - Honeypot Development.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted
provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions
and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions
and the following disclaimer in the documentation and/or other materials provided with the
distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND AN EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

__author__ = 'Are Hansen'
__date__ = '2014, July 25'
__version__ = '0.0.2'


import sys
import re


def IPv4(ipv4_obj):
    """Checks the ipv4_obj, if the object is a string it will be converted to a list object.
    Itterate over the list elements and extract anything that matches the regex of a IPv4 address,
    if the extracted object is not present in the ipv4_list it will be appended to that list. The 
    ipv4_list is sorted and return as the ipv4_sort list. This function searche for an IPv4 address
    containig all four octets. """
    ipv4_list = []
    ipv4_sort = []

    if type(ipv4_obj) == str:
        ipv4_obj = ipv4_obj.split()

    for obj in ipv4_obj:
        matches = re.findall("[\w,\W,\S,\s](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\w,\W,\S,\s,\n]", obj)
        if matches:
            if matches[0] not in ipv4_list:
                ipv4_list.append(matches[0])

    for ipv4 in sorted(ipv4_list):
        ipv4_sort.append(ipv4)

    return ipv4_sort


def IPv4part(ipv4part_str, data_obj):
    """This function will firstly check how many octets are in the ipv4part_str, and alter its regex
    according to that. After altering the regex according to the number of cotets it will then use
    the regex to extract any lines that matches. These lines will be added to the ipv4_match list
    and returned. """
    ipv4_match = []

    octets = len(ipv4part_str[0].split('.'))

    if octets > 4 or octets < 1:
        print 'ERROR: An IPv4 address can only have 4 octets!'
        sys.exit(1)

    if octets == 4:
        oone = ipv4part_str[0].split('.')[0]
        otwo = ipv4part_str[0].split('.')[1]
        otre = ipv4part_str[0].split('.')[2]
        ofou = ipv4part_str[0].split('.')[3]

        for obj in data_obj:
            if re.search(r'{0}\.{1}\.{2}\.{3}'.format(oone, otwo, otre, ofou), obj):
                ipv4_match.append(obj)

    if octets == 3:
        oone = ipv4part_str[0].split('.')[0]
        otwo = ipv4part_str[0].split('.')[1]
        otre = ipv4part_str[0].split('.')[2]

        for obj in data_obj:
            if re.search(r'{0}\.{1}\.{2}\.{3}'.format(oone, otwo, otre, '\d{1,3}'), obj):
                ipv4_match.append(obj)

    if octets == 2:
        oone = ipv4part_str[0].split('.')[0]
        otwo = ipv4part_str[0].split('.')[1]

        for obj in data_obj:
            if re.search(r'{0}\.{1}\.{2}\.{3}'.format(oone, otwo, '\d{1,3}', '\d{1,3}'), obj):
                ipv4_match.append(obj)

    if octets == 1:
        oone = ipv4part_str[0].split('.')[0]

        for obj in data_obj:
            if re.search(r'{0}\.{1}\.{2}\.{3}'.format(oone, '\d{1,3}', '\d{1,3}', '\d{1,3}'), obj):
                ipv4_match.append(obj)

    return ipv4_match


def Email(email_obj):
    """Checks the email_obj, if the object is a string it will be converted to a list object.
    Itterate over the list elements and extract anything that matches the format of an email address
    and append that object to the email_list if its not present. The email_list is sorted and return
    returned as email_sort. """
    email_list = []
    email_sort = []

    if type(email_obj) == str:
        email_obj = email_obj.split()

    for obj in email_obj:
        matches = re.findall(r'[\w.-]+@[\w.-]+\.[\w.-]+', obj)
        if matches:
            if matches[0] not in email_list:
                user_list.append(matches[0])

    for user in sorted(user_list):
        print user


def URL(url_obj):
    """Check the url_obj, if the object is a string it will be converted to a list object. Itterate
    over the list elements and extract anything that matches the format of any URL type and append
    that object to the url_list if not already present. The url_list is sorted and returned as
    url_sort. """
    url_list = []
    url_sort = []

    if type(url_obj) == str:
        url_obj = url_obj.split()

    for obj in url_obj:
        matches = re.findall(r'\b(([\w-]+://?|www[.])[^\s()<>]+(?:\([\w\d]+\)|([^[:punct:]\s]|/)))', obj)
        if matches:
            if matches[0] not in url_list:
                url_list.append(matches[0])

    for url in sorted(url_list):
        url_sort.append(url[0])

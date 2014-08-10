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
__version__ = '0.0.1'


import GeoIP


def cname(ipv4_list):
    """Checks the IPv4 list elements against the GeoIP database and returns a dictionary object
    where the  IPv4 address is the key and the full name of the country is the value."""
    geo = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
    output = []

    for ipv4 in ipv4_list:
        gip = geo.country_name_by_addr(ipv4)
        output.append(gip)

    return output


def ipv4Detailed(ipv4_list):
    """Checks every element in the ipv4_list against the GeoIP database and returns as much
    information as possible. The results will generate a dictionary that uses the IPv4 address as
    the key and appends the details about it to a list, which then makes up the key structure. """
    gi = GeoIP.open('/home/odin/Documents/PY_PKG/__OTHER__/GeoLiteCity.dat', GeoIP.GEOIP_STANDARD)
    info_list = []
    ipv4_dict = {}

    for ipv4 in ipv4_list:
        gir = gi.record_by_name(ipv4)
        
        if gir['country_name'] != None:
            info_list.append('Country: {0:>25}'.format(gir['country_name']))
        
        if gir['city'] != None:
            info_list.append('City: {0:>28}'.format(gir['city']))
        
        if gir['region'] != None:
            info_list.append('Region: {0:>26}'.format(gir['region']))
        
        if gir['region_name'] != None:
            info_list.append('County: {0:>26}'.format(gir['region_name']))

        if gir['postal_code'] != None:
            info_list.append('Zip code: {0:>24}'.format(gir['postal_code']))

        if gir['time_zone'] != None:
            info_list.append('Time zone: {0:>23}'.format(gir['time_zone']))

        if gir['latitude'] != None:
            info_list.append('Latitude: {0:>24}'.format(gir['latitude']))

        if gir['longitude'] != None:
            info_list.append('Longitude: {0:>23}'.format(gir['longitude']))

        ipv4_dict[ipv4] = info_list
        info_list = []

    return ipv4_dict




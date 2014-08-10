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


import operator


def source(items, nol):
    """Formats and prints the results showing source IP stats. """
    banner = '{0:>9}{1:>20}'.format('Hits', 'IP address')
    header = '=' * 36
    stdout_list = []
    
    for key, value in sorted(items.iteritems(), key=operator.itemgetter(1), reverse=True):
        stdout_list.append('{0:>9}   {1}'.format(value, key))

    print '{0}\n {1}'.format(banner, header)
    for std in stdout_list[:nol]:
        print std

    print ''


def origin(items, nol):
    """Formats and prints the results showing country of origin. """
    banner = '{0:>9}{1:>20}'.format('Hits', 'Country of origin')
    header = '=' * 36
    stdout_list = []

    for key, value in sorted(items.iteritems(), key=operator.itemgetter(1), reverse=True):
        stdout_list.append('{0:>9}   {1}'.format(value, key))

    print '{0}\n {1}'.format(banner, header)
    for std in stdout_list[:nol]:
        print std

    print ''


def passwd(items, nol):
    """Formats and prints the results showing password frequency. """
    banner = '{0:>9}{1:>11}'.format('Tries', 'Password')
    header = '=' * 36
    stdout_list = []

    for key, value in sorted(items.iteritems(), key=operator.itemgetter(1), reverse=True):
        stdout_list.append('{0:>9}   {1}'.format(value, key))

    print '{0}\n {1}'.format(banner, header)
    for std in stdout_list[:nol]:
        print std

    print ''


def usrnames(items, nol):
    """Formats and prints the results showing username frequency. """
    banner = '{0:>9}{1:>11}'.format('Tries', 'Username')
    header = '=' * 36
    stdout_list = []

    for key, value in sorted(items.iteritems(), key=operator.itemgetter(1), reverse=True):
        stdout_list.append('{0:>9}   {1}'.format(value, key))

    print '{0}\n {1}'.format(banner, header)
    for std in stdout_list[:nol]:
        print std
    print ''


def combinations(items, nol):
    """Formats and prints the results showing user/password combination frequency. """
    banner = '{0:>9}{1:>15}'.format('Tries', 'Combinations')
    header = '=' * 36
    stdout_list = []

    for key, value in sorted(items.iteritems(), key=operator.itemgetter(1), reverse=True):
        stdout_list.append('{0:>9}   {1}'.format(value, key))

    print '{0}\n {1}'.format(banner, header)
    for std in stdout_list[:nol]:
        print std
    print ''


def foundlogin(items, nol):
    banner = '  {0:<12} {1:<10} {4:<16} {5:<8} {2:<11} {3:<9}'.format('Date', 'Time', 'User',
                                                            'Password', 'IP address', 'Origin')
    header = '=' * 85
    stdout_list = []
    result = []

    for itt in items:
        login = '  {0:<12} {1:<10} {4:<16} {5:<8} {2:<11} {3:<4}'.format(itt[0], itt[1], itt[2],
                                                                       itt[3], itt[4], itt[5])
        result.append(login)

    for data in sorted(result, reverse=True):
        stdout_list.append(data)

    if len(result) == 0:
        print '  {0}\n{1}'.format(banner, header)
        print '\t\t\tNo successful logins yet'
        print ''
        sys.exit(1)

    print '{0}\n{1}'.format(banner, header)
    for std in stdout_list[:nol]:
        print std
    print ''


def summary(ltime, attnr, ipv4nr, cnr, usrnr, uqpaswd, uqcomb, logsnr, mwtnr, umvmd5, umurl, umips, 
            umnam, uircip, uirccn, uhttpip, uhttpcn, synfld, udpfld):
    """Formats and outputs the attack summary. """
    attprd = float(attnr) / len(logsnr)
    attprh = attprd / 24
    attprm = attprh / 60
    attprs = attprm / 60
    attprc = float(attnr) / cnr
    attpri = float(attnr) / ipv4nr

    print '\n{0:>50}'.format('--- Bifrozt Summary ---')
    print '\n{0:>56}'.format('============== Period ==============')
    print '{0:>33}{1:>23}'.format('First attack:', ltime[0])
    print '{0:>34}{1:>22}'.format('Latest attack:', ltime[1])

    print '\n ============== Total ===============   ========== Attack Average =========='
    print '{0:>9}{1:>28}{2:>15}{3:>24.3f}'.format('Attacks:', attnr, 'Per country:', attprc)
    print '{0:>11}{1:>26}{2:>12}{3:>27.3f}'.format('Countries:', cnr, 'Per IPv4:', attpri)
    print '{0:>6}{1:>31}{2:>11}{3:>28.3f}'.format('IPv4:', ipv4nr, 'Per day:', attprd)
    print '{0:>11}{1:>26}{2:>12}{3:>27.3f}'.format('Passwords:', uqpaswd, 'Per hour:', attprh)
    print '{0:>11}{1:>26}{2:>11}{3:>28.3f}'.format('Usernames:', usrnr, 'Per min:', attprm)
    print '{0:>8}{1:>29}{2:>11}{3:>28.3f}'.format('Combos:', uqcomb, 'Per sec:', attprs)

    print '\n ========= Downloaded Files =========   ========= Outbound traffic ========='
    print '{0:>13}{1:>24}{2:>21}{3:>18}'.format('Total files:', mwtnr, 'HTTP destinations:', uhttpip)
    print '{0:>13}{1:>24}{2:>17}{3:>22}'.format('Unique URLs:', umurl, 'IRC countries:', uirccn)
    print '{0:>12}{1:>25}{2:>20}{3:>19}'.format('Unique MD5:', umvmd5, 'IRC destinations:', uircip)
    print '{0:>18}{1:>19}{2:>21}{3:>18}'.format('Unique filenames:', umnam, 'Blocked SYN-flood:', synfld)
    print '{0:>18}{1:>19}{2:>21}{3:>18}\n'.format('Unique attackers:', umips, 'Blocked UDP-flood:', udpfld)


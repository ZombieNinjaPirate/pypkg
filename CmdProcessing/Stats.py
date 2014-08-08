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


import os
import sys
from Bifrozt.Calculate.Average import mean
from Bifrozt.Count.Lists import element, nrOfItems, uniqElements
from Bifrozt.FileProcessing.Read import filelines
from Bifrozt.Find.Addresses import IPv4, IPv4part
from Bifrozt.Find.Files import locate
from Bifrozt.Find.LogData import startEnd, logKeyword, logIndex, logIndexKey
from Bifrozt.Find.IPgeo import cname, ipv4Detailed
from Bifrozt.HonSSH.DailyLogs import sourceIPv4, passwords, users, combos, access
from Bifrozt.HonSSH.GEO import accessCC
from Bifrozt.HonSSH.Output import source, origin, passwd, usrnames, combinations, foundlogin, summary
from Bifrozt.System.Output import fwIRC


def honsshData(args):
    workdir = os.getcwd()
    logfiles = []
    loglines = []
    number = 50

    if not os.path.isdir(args.hondir[0]):
        print 'ERROR: {0} does not appear to exist!'.format(args.hondir[0])
        sys.exit(1)

    honssh_logs = filelines(locate(args.hondir[0], '20'))
    
    if args.number:
        number = int(args.number)

    for log, logdata in honssh_logs.items():
        logfiles.append(log)

        for lines in logdata:
            loglines.append(lines.rstrip())

    if args.summry:
        malwr_lines = []
        os.chdir(workdir)
        malwr_log = filelines(locate(args.hondir[0], 'downloads.log'))

        for logfile, malwrlines in malwr_log.items():
            for lines in malwrlines:
                malwr_lines.append(lines)

        logstimed = startEnd(sorted(loglines), ',', 1)
        attacknum = nrOfItems(loglines)
        sourceips = sourceIPv4(loglines)
        uniqueips = uniqElements(sourceips)
        ipv4numbr = nrOfItems(uniqueips)
        findcname = cname(sourceips)
        countname = element(findcname, None)
        countrynr = nrOfItems(countname.keys())
        usedunames = users(loglines)
        user_items = element(usedunames, None)
        uniqusrnam = uniqElements(user_items)
        usernamynr = nrOfItems(uniqusrnam)
        usedpasswd = passwords(loglines)
        pass_items = element(usedpasswd, None)
        uniqpasswd = nrOfItems(pass_items.keys())
        attemptedc = combos(loglines)
        comb_items = element(attemptedc, None)
        uniqcombos = nrOfItems(comb_items.keys())
        malwrmd5 = logIndex(malwr_lines, 4, ',')
        uniqmlwr = uniqElements(malwrmd5)
        malwrtnr = len(malwr_lines)
        umlwrmd5 = len(uniqmlwr)
        summary(logstimed, attacknum, ipv4numbr, countrynr, usernamynr, uniqpasswd, uniqcombos,
                logfiles, malwrtnr, umlwrmd5)

    if args.source:
        sourceips = sourceIPv4(loglines)
        countdips = element(sourceips, None)
        source(countdips, number)

    if args.origin:
        sourceips = sourceIPv4(loglines)
        findcname = cname(sourceips)
        countname = element(findcname, None)
        origin(countname, number)

    if args.passwd:
        usedpasswd = passwords(loglines)
        pass_items = element(usedpasswd, None)
        passwd(pass_items, number)

    if args.usrnam:
        usedunames = users(loglines)
        user_items = element(usedunames, None)
        usrnames(user_items, number)

    if args.combos:
        attemptedc = combos(loglines)
        comb_items = element(attemptedc, None)
        combinations(comb_items, number)

    if args.access:
        gainaccess = access(loglines)
        geoipslook = accessCC(gainaccess)
        foundlogin(geoipslook, number)

    if args.qpasswd:
        searchdata = IPv4part(args.qpasswd, loglines)
        querpasswd = passwords(searchdata)
        pass_items = element(querpasswd, None)
        passwd(pass_items, number)

    if args.qusrnam:
        searchdata = IPv4part(args.qusrnam, loglines)
        querunames = users(loglines)
        user_items = element(querunames, None)
        usrnames(user_items, number)

    if args.qcombos:
        searchdata = IPv4part(args.qcombos, loglines)
        attemptedc = combos(searchdata)
        comb_items = element(attemptedc, None)
        combinations(comb_items, number)


def firewallData(args):
    logfiles = []
    loglines = []

    if not os.path.isdir(args.fwldir[0]):
        print 'ERROR: {0} does not appear to exist!'.format(args.fwldir[0])
        sys.exit(1)

    firewall_logs = filelines(locate(args.fwldir[0], 'firewall'))

    for log, logdata in firewall_logs.items():
        logfiles.append(log)

        for lines in logdata:
            loglines.append(lines.rstrip())


    # Extract the IRC destination addresses from the firewall logs
    if args.fwirc:
        findirc = logKeyword(loglines, 'IRC')
        ircdest = logIndexKey(findirc, None, 'DST')
        ircipv4 = logIndex(ircdest, -1, '=')
        uniqirc = uniqElements(ircipv4)
        ircdtil = ipv4Detailed(uniqirc)
        fwIRC(ircdtil)


def dataSummary(args):
    #   - summary    #
    #       - average number of attacks pr/country
    #       - average number of attacks pr/ip address
    #       - average number of attacks pr/minute
    #
    # if not os.path.isdir(args.hondir[0]):
    #     print 'ERROR: {0} does not appear to exist!'.format(args.hondir[0])
    #     sys.exit(1)
    owd = os.getcwd()
    logfiles = []
    loglines = []

    honssh_logs = filelines(locate(args.hondir[0], '20'))

    for log, logdata in honssh_logs.items():
        logfiles.append(log)

        for lines in logdata:
            loglines.append(lines.rstrip())

    os.chdir(owd)
    # if not os.path.isdir(args.fwldir[0]):
    #     print 'ERROR: {0} does not appear to exist!'.format(args.fwldir[0])
    #     sys.exit(1)

    fwfiles = []
    fwlines = []

    firewall_logs = fwlines(locate(args.fwldir, 'firewall'))

    for fwlog, fwdata in firewall_logs.items():
        fwfiles.append(fwlog)

        for lines in fwdata:
            fwlines.append(lines.rstrip())



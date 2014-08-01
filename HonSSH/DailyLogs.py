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



def sourceIPv4(loglines):
    """Splits the loglines on ',' and assumes that there will be an IP address at index[1], this IP
    address is appended to the output list and returned from the function. """
    output = []

    for line in loglines:
        line = line.split(',')
        output.append(line[1])

    return output


def passwords(loglines):
    """Splits the loglines on ',' and assumes that there will be a usename at index[3], which will
    be appended to the output list and returned from the function. """
    output = []

    for line in loglines:
        line  = line.split(',')
        output.append('{0}'.format(line[3]))

    return output


def passwords(loglines):
    """Splits the loglines on ',' and assumes that there will be a password at index[3], which will
    be appended to the output list and returned from the function. """
    output = []

    for line in loglines:
        line  = line.split(',')
        output.append('{0}'.format(line[3]))

    return output


def users(loglines):
    """Splits the loglines on ',' and assumes that there will be a username at index[2], which will
    be appended to the output list and returned from the function. """
    output = []

    for line in loglines:
        line  = line.split(',')
        output.append('{0}'.format(line[2]))

    return output


def combos(loglines):
    """Splits the loglines on ',' and assumes that there will be a username at index[2] and a
    password at index[4], which will be appended to the output list and returned from the function.
    """
    output = []

    for line in loglines:
        line  = line.split(',')
        output.append('{0}/{1}'.format(line[2], line[3]))

    return output


def access(loglines):
    """Checks for successful logins in the HonSSH loglines. This is done by itterating trough the
    loglines while splitting on ','. The last index of the list item thats created by doing so will
    either be a 0 (failed login) or a 1 (successful login). Any line with a 1 in index[4] will be
    appended to the output list and returned from the function. """
    output = []

    for line in loglines:
        line = line.split(',')
        if '1' in line[4]:
            output.append('{0} {1} {2} {3}'.format(line[0], line[1], line[2], line[3]))

    return output
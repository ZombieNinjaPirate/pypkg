"""This module can be used to extract speciffic types of data from a log file. """


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


def startEnd(loglines, sparam, index):
    """Expects that the loglines object is a list containg lines of a log file. From the first and
    last line of the log file it will grab the time stamps. Even tho logfiles might differ in what
    data they contain and how they are constructed, they have one thing in common. The beginning of 
    each line is a timestamp. The rest of the line might be divided by whitespaces, commas or other
    characters. To create a list object from the lines, the function will split the lines using the
    split parameter, sparam, and then read the elements in that list from list[0] to list[index]. 
    This operation is preformed on the first and last line of the loglines before they are returned
    as a tuple. """
    # If sparam is None, split by whitespace
    if sparam == None:
        sparam = ' '

    start = ''.join(loglines[0].split(sparam)[0:index][0])
    ended = ''.join(loglines[-1].split(sparam)[0:index][0])
 
    return start, ended
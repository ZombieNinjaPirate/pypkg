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


def logKeyword(loglines, kword):
    """Searches trough the loglines containing the kword. Any loglines matching that word is
    appended to the kw_list and returned. """
    kw_list = []

    for line in loglines:
        if kword in line:
            kw_list.append(line)

    return kw_list


def logIndex(log_obj, index, sparam):
    """Splits the lines in the log_obj at the sparam and extracts a element from the resulting list
    in the obj residing ad the given index position and appends it to the index_list. The index_list
    is returned once all the objects in the log_obj have been processed. """
    index_list = []

    for obj in log_obj:
        index_list.append(obj.split(sparam)[index])

    return index_list


def logIndexKey(log_obj, sparam, kword):
    """Splits the lines in the log_obj at the sparam and itterates over the resulting list, if the
    resulting list contais an element with the kword it adds that element to the ikey_list which is
    returned. """
    ikey_list = []

    for obj in log_obj:
        obj_list = obj.split(sparam)

        for oline in obj_list:
            if kword in oline:
                ikey_list.append(oline)

    return ikey_list










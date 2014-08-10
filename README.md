Bifrozt-pypkg
=============

Copyright (c) 2014, Are Hansen - Honeypot Development.

Contain modules that's used on Bifrozt (http://sourceforge.net/projects/bifrozt/).
Some of them are unique to Bifrozt and HonSSH while others can be used on any other system where Python has been installed. This has only been tested with Python 2.7.

External packages:
- GeoIP
- hurry.filesize


Example of Bifrozt summary output:


                               --- Bifrozt Summary ---

                        ============== Period ==============
                        First attack:    2014-07-28 18:27:55
                        Latest attack:   2014-08-10 14:05:51

    ============== Total ===============   ========== Attack Average ==========
    Attacks:                       36308   Per country:                1910.947
    Countries:                        19   Per IPv4:                    235.766
    IPv4:                            154   Per day:                    2593.429
    Passwords:                      7184   Per hour:                    108.060
    Usernames:                       555   Per min:                       1.801
    Combos:                         7784   Per sec:                       0.030

    ========= Downloaded Files =========   ========= Outbound traffic =========
    Total files:                     327   HTTP destinations:                84
    Unique URLs:                      25   IRC countries:                     6
    Unique MD5:                       14   IRC destinations:                 11
    Unique filenames:                 14   Blocked SYN-flood:            258655
    Unique attackers:                 16   Blocked UDP-flood:            225406



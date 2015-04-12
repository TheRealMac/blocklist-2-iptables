# blocklist-2-iptables
Perl Script to manage iptables rules containing IP-Adresses from various download sources (i.e. blocklist.de) 

# idea behind
a simple way to add known spammers and attackers periodically to Linux' iptables (without ipset)

Currently the lists of IP-addresses are coming from https://www.blocklist.de/en/index.html, it's possible to add other sources too.
The sources can be categorized (@types) so you can define your own types, these types are used for the iptables chain names too.

This script
* collects the IP-Adresses from the given URLs
* creates a Class-C net if possible to reduce number of rules
* checks for duplicates
* adds and enable chains to iptables
* add rules to created chains

# Usage
<pre>./blocklist.pl [-s,-d,-h] [-q] [-flush,-init]

Examples:       ./blocklist.pl -h
Examples:       ./blocklist.pl -s
Examples:       ./blocklist.pl -s -q
Examples:       ./blocklist.pl -s -flush
Examples:       ./blocklist.pl -d

-h      help - displaying these information
-d      debug - what would be done
-s      sure - just do it
-flush  flush the iptable rules
-init   flushing the iptable rules too
-q      quiet - don't display the summary after processing</pre>

# Tipps
use it in your cronjobs
<pre>#protecting the server
*/30 * * * *    /path_to_your_scripts/blocklist.pl -s -q
15 */6 * * *    /path_to_your_scripts/blocklist.pl -flush -s</pre>


# Requirements
Linux Server with iptables<br/>
Perl 5.x<br/>
LWP::Simple

# Known issues
on some virtual servers there are limits to the maximum number of rules - ipset would be a nice solution but it's not possible to use it on OpenVZ containers

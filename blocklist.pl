#!/usr/bin/perl -sw
#
# blocklist.pl - Version 1.2
#		2015 Apr 12th
# 
# Copyright (C) 2015 Mac Winter - www.homac.at
#
# latest Version and Git repository available at https://github.com/TheRealMac/blocklist-2-iptables
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
#


use LWP::Simple;
use strict;

#switches
our($s,$d,$h,$init,$q,$flush);

$s = $d?0:$s;
my $sure = $s;
my $help = $h;
my $quiet = $q;
my $debug = $d;

# displaying help
if ($help || (!$sure && !$debug && !$init && !$flush)) {
	print "Script to add iptable rules with IP-Adresses from blocklist.de\n";
	print "Usage:\t\t$0 [-s,-d,-h] [-q] [-flush,-init]\n\n";
	print "Examples:\t$0 -h\n";
	print "Examples:\t$0 -s\n";
	print "Examples:\t$0 -s -q\n";
	print "Examples:\t$0 -s -flush\n";
	print "Examples:\t$0 -d\n\n";
	print "-h\thelp - displaying these information\n";
	print "-d\tdebug - what would be done\n";
	print "-s\tsure - just do it\n";
	print "-flush\tflush the iptable rules\n";
	print "-init\tflushing the iptable rules too\n";
	print "-q\tquiet - don't display the summary after processing\n\n";
	exit;
}

my %urls = ("ssh" => 				"http://lists.blocklist.de/lists/ssh.txt",
						"mail" => 			"http://lists.blocklist.de/lists/mail.txt",
						"imap" => 			"http://lists.blocklist.de/lists/imap.txt",
						"strong" =>			"http://lists.blocklist.de/lists/strongips.txt",
						"apache" => 		"http://lists.blocklist.de/lists/apache.txt",
						"ftp" => 				"http://lists.blocklist.de/lists/ftp.txt",
						"sip" => 				"http://lists.blocklist.de/lists/sip.txt", #voip ...
						"bots" => 			"http://lists.blocklist.de/lists/bots.txt",	#All IP addresses which have been reported within the last 48 hours as having run attacks attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki). 
						"irc" => 				"http://lists.blocklist.de/lists/ircbot.txt",
						"bruteforce" => "http://lists.blocklist.de/lists/bruteforcelogin.txt",	#wp-logins
						"lastIps" => 		"http://api.blocklist.de/getlast.php?time=3600"
					 );

#types of lists to import
my @types;
# Webserver: @types = ("ssh","strong","apache","bots","bruteforce");
# Mailserver: @types = ("ssh","mail","imap","strong");
@types = ("ssh","strong","apache","bots","bruteforce");

#count starting iptables lines for information purposes
if (!$quiet) {
	my $iptablesLines = `/sbin/iptables -nL | wc -l`;
	chomp $iptablesLines;
	print "Lines in iptables before: $iptablesLines\n";
}

#Flush chains
if ($flush || $init) {
	for my $type (@types,"lastIps") {
		my $chain = "blocklist-$type";
		system("/sbin/iptables -nL $chain > /dev/null 2>&1");
		if ($? == 0) {
			my $sysaction = "/sbin/iptables -F $chain";
			if ($debug) {
				print "Flush Chain $chain:\n\t$sysaction\n";
			}
			if ($sure) {
				system($sysaction);
				system("sleep 1");
			}
		}
	}
}

for my $type (@types) {
	if ($urls{$type}) {

		my $rulesCount = 0;

		my $chain = "blocklist-$type";

		#get URLS
		my $txt = get($urls{$type});
		next if (!$txt);
		#check first IP
		my @ips = split("\n",$txt);
		next if (!isIp($ips[0]));

		my @currentIptablesEntries = `/sbin/iptables -nL | awk '{print \$4}' | sort | uniq | grep ^[1-9]`;
		my %iptablesIPs;
		for my $ip (@currentIptablesEntries) {
			chomp $ip;
			$iptablesIPs{$ip} = 1;
		}

		#chain already created?
		system("/sbin/iptables -nL $chain > /dev/null 2>&1");
		if ($? != 0) {
			#Create chain
			my $sysaction = "/sbin/iptables -N $chain";
			if ($debug) {
				print "Create Chain $chain:\n\t$sysaction\n";
			}
			if ($sure) {
				system($sysaction);
			}
		}

		my %networks;
		#cleanup IPs
		for my $ip (@ips) {
			##ends with zero (0)
			if ($ip =~ /\.0$/) {
				$networks{$ip} = 1;
			}
		}


		#list of IPs
		for my $ip (@ips) {
			my $tIp = $ip;
			$tIp =~ s/\.\d+$//;
			#already blocked?
			next if (exists($iptablesIPs{$ip}) || exists($iptablesIPs{"$tIp.0/24"}));

			if (isIp($ip) && !exists($networks{"$tIp.0"})) {
				my $sysaction = "/sbin/iptables -I $chain -s $ip -j DROP";
				$rulesCount++;
				if ($debug) {
					print " * $sysaction\n";
				}
				if ($sure) {
					system($sysaction);
				}
			}
		}
		#list of networks
		for my $network (keys %networks) {
			# next if (exists($iptablesIPs{"$network/24"}));
			my $sysaction = "/sbin/iptables -I $chain -s $network/24 -j DROP";
			$rulesCount++;
			if ($debug) {
				print " * $sysaction\n";
			}
			if ($sure) {
				system($sysaction);
			}
		}

		#rule enganged???
		system("/sbin/iptables -nL | grep ^$chain > /dev/null 2>&1");
		if ($? != 0) {
			my $sysaction = "/sbin/iptables -I INPUT -j $chain";
			#Activate Rule
			if ($debug) {
				print "Activate Rule:\n\t$sysaction\n";
			}
			if ($sure) {
				system($sysaction);
			}
		}
		if (!$quiet) {
			print "$chain: added $rulesCount Rules\n";
		}
	}
}

#count finishing iptables lines
if (!$quiet) {
	my $iptablesLines = `/sbin/iptables -nL | wc -l`;
	chomp $iptablesLines;
	print "Lines in iptables after: $iptablesLines\n";
}

exit;


sub isIp {
	my $ip = shift;
	return $ip =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
}

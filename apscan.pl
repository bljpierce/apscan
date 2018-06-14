#############################################################################
#                               apscan.pl                                   #
#                                                                           #
#  Scans for wireless access points and displays various information about  #
#  them. It works by parsing the output of the iwlist scan command and      #
#  turning it into something more readable. Requires the iwtools package.   #
#                                                                           #
#          Usage: perl apscan.pl [network interface name]                   #
#                                                                           #
#                     Copyright (c) 2016, Barry Pierce                      #
#                                                                           #
#############################################################################

#!/usr/bin/perl
use strict;
use warnings;
use feature 'say';

if (!@ARGV) {
    print "usage: perl apscan.pl [network interface name]\n";
    exit;
}

my $dev = $ARGV[0];
my $iwlist = `which iwlist`;
chomp($iwlist);
my @iwlist_output = `$iwlist $dev scan`;




# parse iwlist output and store access point info in hoh:
#    {
#        bssid1 = { channel => v, sig => v, security => v, essid = v },
#        bssid2 = { channel => v, sig => v, security => v, essid = v },
#        bssid3 = { channel => v, sig => v, security => v, essid = v },
#    }
my %ap;
my $bssid;
for (@iwlist_output) {
    if (/Address: \s+ (.*)/x) {
        $bssid = $1;
        $ap{$bssid} = {};
    }
    elsif (/Channel:(\d+)/) {
        $ap{$bssid}->{channel} = $1;
    }
    elsif (/Signal \s+ level= (-\d+)/x) {
        $ap{$bssid}->{sig} = $1;
    }
    elsif (/Encryption key:(on|off)/) {
        $ap{$bssid}->{encryption} = $1;
        if ($1 eq 'off') {
            $ap{$bssid}->{security} = 'OPEN';
        }
    }
    elsif (/ESSID:"(.*)"/) {
        $ap{$bssid}->{essid} = $1;
    }
    elsif (/IE:.*(WPA|WPA2)/) {
        $ap{$bssid}->{security} = $1;
    }
    elsif (/Group \s+ Cipher \s+ : \s+ (.*)/x) {
        $ap{$bssid}->{security} .= "-$1";
    }
    elsif (/Authentication \s+ Suites .*: \s+ (.*)/x) {
        $ap{$bssid}->{security} .= "/$1";
    }
}

if (!keys %ap) {
    print "No scan results.\n";
    exit;
}

# print table of access point info
my $line = "-" x 70;
print "$line\n";
printf "     %6s %8s %6s %12s %16s\n", qw/BSSID CH SIG SECURITY ESSID/;
print "$line\n";
# sort access point info by signal strength
for my $bssid (sort { $ap{$b}->{sig} <=> $ap{$a}->{sig} } keys %ap) {
    printf
        "%-18s %-4d %-5d %-17s %s\n",
        $bssid,
        @{ $ap{$bssid} }{qw/channel sig security essid/};
}

print "$line\n";

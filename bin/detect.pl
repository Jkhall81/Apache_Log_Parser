#!/usr/bin/perl

use strict;
use warnings;
use lib 'lib';
use ThreatDetector::Parser;
use ThreatDetector::Classifier;
use ThreatDetector::Dispatcher;

use Getopt::Long;
use File::Basename;
use Time::HiRes qw(gettimeofday);

# ----- CONFIG -----
my $log_file = '/var/log/apache2/access.log';
my $output_log = 'logs/threats.log';
my $verbose = 0;

GetOptions(
    'logfile=s' => \$log_file,
    'verbose' => \$verbose,
);

open(my $fh, '<', $log_file) or die "Can't open $log_file: $!";
open(my $out, '>>', $output_log) or die "Can't write to $output_log: $!";

while (my $line = <$fh>) {
    chomp $line;

    my $entry = ThreatDetector::Parser::Parse_log_line($line);
    next unless $entry;

    # Classify threat type
    my @threats = ThreatDetector::Classifier::classify($entry);
    next unless @threats;

    for my $threat_type (@threats) {
        my $result = ThreatDetector::Dispatcher:;handle($threat_type, $entry);

        if ($result) {
            my ($sec, $micros) = gettimeofday;
            my $timestamp = scalar localtime($sec);

            print $out "$timestamp [$threat_type] $result\n";
            print "Detected [$threat_type]: $result\n" if $verbose;
        }
    }
}

close($fh);
close($out);
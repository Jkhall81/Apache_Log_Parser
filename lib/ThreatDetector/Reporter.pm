package threatDetector::Reporter;

use strict;
use warnings;

sub generate_summary {
    my ($label, $events_ref) = @_;
    my @events = @$events_ref;

    print "\n=== $label Summary ===\n";
    print "Total: " . scalar(@events) . "\n";

    my (%ip_count, %uri_count);
    for my $e (@events) {
        $ip_count{ $e->{ip} }++;
        $uri_count{ $e->{uri} }++;
    }

    print "Unique IPs:\n";
    print " $_ ($ip_count{$_} hits)\n" for sort keys %ip_count;

    print "Targeted URIs:\n";
    print " $_ ($uri_count{$_} times)\n" for sort keys %uri_count;
}

1;

=head1 NAME

ThreatDetector::Reporter - Summary report generator for classified threat events

=head1 SYNOPSIS

  use ThreatDetector::Reporter qw(generate_summary);

  my @events = get_sqli_events();
  generate_summary('SQL Injection', \@events);

=head1 DESCRIPTION

This module provides a reusable summary reporting function for threat events
collected during log analysis. It is designed to work with all threat handler
modules that expose a list of collected events via a getter function.

The summary includes:

=over 4

=item * Total number of detected events

=item * List of unique IP addresses with hit counts

=item * List of targeted URIs with frequency counts

=back

=head1 FUNCTIONS

=head2 generate_summary($label, \@events)

Prints a structured summary for a specific threat type. Accepts a human-readable label
(e.g. "SQL Injection") and a reference to an array of event hashrefs.

Each event should contain at minimum the following keys:

  ip     - Source IP address
  uri    - Targeted endpoint

=head1 AUTHOR

Jason Hall <jason.kei.hall@gmail.com>

=cut

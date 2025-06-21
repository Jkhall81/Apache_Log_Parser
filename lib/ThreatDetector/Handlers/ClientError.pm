package ThreatDetector::Handlers::ClientError;

use strict;
use warnings;
use Exporter 'import';
use JSON;
use Time::HiRes qw(gettimeofday);

our @EXPORT_OK = qw(handle_client_error);

sub handle_client_error {
    my ($entry) = @_;
    my ($sec, $micro) = gettimeofday();

    my $alert = {
        timestamp => "$sec.$micro",
        type => 'client_error',
        ip => $entry->{ip},
        method => $entry->{method},
        uri => $entry->{uri},
        status => $entry->{status},
        user_agent => $entry->{user_agent},
    };

    print encode_json($alert) . "\n";
}

=head1 NAME

ThreatDetector::Handlers::ClientError - Handler for HTTP 4xx client errors

=head1 SYNOPSIS

  use ThreatDetector::Handlers::ClientError qw(handle_client_error);

  handle_client_error($entry);

=head1 DESCRIPTION

Prints a JSON alert for any Apache log entry resulting in a 4xx client error.
Useful for tracking broken links, unauthorized access, or misconfigured bots.

=head1 AUTHOR

Jason Hall <jason.kei.hall@gmail.com>

=cut
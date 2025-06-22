package ThreatDetector::Handlers::EncodedPayload;

use strict;
use warnings;
use Exporter 'import';
use JSON;
use Time::HiRes qw(gettimeofday);

our $VERBOSE = 0;
our @EXPORT_OK = qw(handle_encoded);

sub handle_encoded {
    my ($entry) = @_;
    my ( $sec, $micro ) = gettimeofday();

    my $alert = {
        timestamp  => "$sec.$micro",
        type       => 'encoded_payload',
        ip         => $entry->{ip},
        method     => $entry->{method},
        uri        => $entry->{uri},
        status     => $entry->{status},
        user_agent => $entry->{user_agent},
    };
    print encode_json($alert) . "\n" if $VERBOSE;
}

1;

=head1 NAME

ThreatDetector::Handlers::EncodedPayload - Handler for encoded payload attempts

=head1 SYNOPSIS

  use ThreatDetector::Handlers::EncodedPayload qw(handle_encoded);

  handle_encoded($entry);

=head1 DESCRIPTION

Prints a JSON alert for requests that contain suspiciously encoded characters (e.g. %2e, %3c) which may indicate obfuscated payloads or bypass attempts. Often a precursor to more serious attacks like XSS, path traversal, or command injection.

=head1 AUTHOR

Jason Hall <jason.kei.hall@gmail.com>

=cut

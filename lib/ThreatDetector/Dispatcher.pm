package ThreatDetector::Dispatcher;

use strict;
use warnings;
use JSON;
use File::Basename;
use Time::HiRes qw(gettimeofday);

my %handlers = (
    sql_injection => \&handle_sql_injection,
    client_error => \&handle_client_error,
    command_injection => \&handle_command_injection,
    directory_traversal => \&handle_directory_traversal,
    xss_attempt => \&handle_xss,
    encoded_payload => \&handle_encoded,
    scanner_fingerprint => \&handle_scanner,
    http_method_abuse => \&handle_http_method,
    # Will add a few more later
);

sub dispatch {
    my ($entry, @threats) =@_;
    return unless $entry && @threats;

    for my $threat (@threats) {
        if (exists $handlers{$threat}) {
            $handlers{$threat}->($entry);
        } else {
            warn "[Dispatcher] No handler for threat type: $threat\n";
        }
    }
}
#!/usr/bin/perl

use strict;
use warnings;
use File::Slurp;
use IPC::System::Simple qw(system capture);
use Term::ANSIColor;
use JSON;

my $key_path     = "$ENV{HOME}/.ssh/id_rsa.pub";
my $private_key  = "$ENV{HOME}/.ssh/id_rsa";

# Targets — optional "log" entry overrides default
my @targets = (
    { ip => '65.132.159.77',  user => 'root' },
    { ip => '65.132.159.76',  user => 'root' },
    { ip => '67.132.250.181', user => 'root' },
    { ip => '67.132.250.182', user => 'root' },
    { ip => '206.80.213.28',  user => 'root' },
    { ip => '206.80.213.27',  user => 'root' },
);

# Step 1: Ensure SSH key exists
unless (-e $key_path) {
    print colored("No SSH key found, generating...\n", 'yellow');
    system("ssh-keygen -t rsa -b 4096 -f $private_key -N ''");
}

# Step 2: Loop over each target
for my $host (@targets) {
    my ($ip, $user) = ($host->{ip}, $host->{user});
    my $remote = "$user\@$ip";

    print colored("\nConnecting to $remote...\n", 'cyan');

    # Step 2a: Prime known_hosts (fingerprint)
    print colored("Accepting host fingerprint for $ip if needed...\n", 'magenta');
    system("ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 $remote 'echo ok' >/dev/null 2>&1");

    # Step 2b: Check if key access works
    my $test = system("ssh -o BatchMode=yes -o ConnectTimeout=5 $remote 'echo ok' >/dev/null 2>&1");

    if ($test != 0) {
        print colored("No key access — using ssh-copy-id...\n", 'yellow');
        system("ssh-copy-id $remote");
    } else {
        print colored("Key-based SSH OK\n", 'green');
    }

    # Step 3: If log path is defined, override config
    if ($host->{log}) {
        print colored("Custom config with log path: $host->{log}\n", 'blue');

        my $custom_config = encode_json({
            logfile     => $host->{log},
            output_log  => "~/ThreatDetector/logs",
            verbose     => JSON::false,
        });

        my $tmp_cfg = "/tmp/config_$ip.json";
        write_file($tmp_cfg, $custom_config);

        system("scp $tmp_cfg $remote:~/ThreatDetector/config/config.json");
    } else {
        print colored("Using default config.json on remote.\n", 'blue');
    }

    # Step 4: Run detect.pl remotely
    print colored("Running detect.pl on $remote...\n", 'bright_yellow');
    system("ssh $remote 'cd ~/ThreatDetector && perl bin/detect.pl'");
}
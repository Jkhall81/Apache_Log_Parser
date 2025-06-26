#!/usr/bin/perl

use strict;
use warnings;
use version;
use Module::CoreList;

my $min_perl = version->declare('5.10.0');

my $current = $^V;
if ($current < $min_perl) {
    die "Perl version $current is too old.  Require $min_perl or higher.\n";
}
print "Perl version is $current\n";

my $makefile = 'Makefile.PL';
open my $fh, '<', $makefile or die "Cannot open $makefile: $!";
my %modules;

while (<$fh>) {
    if (/^\s*'([\w:]+)'\s*=>\s*\d+,?/) {
        my $mod = $1;
        next if Module::CoreList::is_core($mod);
        $modules{$mod} = 1;
    }
} 
close $fh;

print "\n Checking modules from PREREQ_PM...\n";

for my $mod (sort keys %modules) {
    eval "use $mod";
    if ($@) {
        print "Missing: $mod\n";
    } else {
        print "Found: $mod\n";
    }
}
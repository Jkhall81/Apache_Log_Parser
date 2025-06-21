use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakeFile(
    NAME => 'ThreatDetector',
    VERSION_FROM => 'lib/ThreatDetector/Parser.pm',
    AUTHOR => 'Jason Hall <jason.kei.hall@gmail.com>',
    ABSTRACT => 'Modular Apache Log Threat Detection for Vicidial',
    LICENSE => 'perl',
    EXE_FILES => ['bin/detect.pl'],
    PREREQ_PM => {
        'strict' => 0,
        'warnings' => 0,
        'URI::Escape' => 0,
        'JSON' => 0,
        'DBI' => 0,
        'DBD:SQLite' => 0,
        'File::Basename' => 0,
        'Time::HiRes' => 0,
        'Getopt::Long',
    },
    META_MERGE => {
        resources => {
            repository => 'https://github.com/Jkhall81/apache-threat-detector',
        },
    },
);
#!perl

use strict;
use warnings;

if ($#ARGV != 0) {
    print "Wrong number argiments.\n Usage: make-config.pl <peer_count>\n";
}

my $count = $ARGV[0];

my @sk;
my @pk;

print "Peer count: $count\n";

for (my $i = 0; $i < $count; $i++) {

    my $out = "";

    open(my $fh, '-|', 'signer -dv 2>&1') or die $!;
    while (my $line = <$fh>) {
        $out = "$out$line";
    }

    if ($out =~ /^sk:\s([0-9a-z]{64})$/m) {
        push @sk, $1;
    }

    if ($out =~ /^pk:\s([0-9a-z]{64})$/m) {
        push @pk, $1;
    }

}

open(my $scriptfh, '>', "run-signers.sh") or die $!;
print $scriptfh "#!/bin/sh\n\n";

for (my $i = 0; $i < $count; $i++) {
    my $texti = $i +1;
    my $port = 12001 + $i;
    open(my $configfh, '>', "signer$texti.conf") or die $!;

    print $scriptfh "signer --config signer$texti.conf -vi text > signer$texti.log 2>&1 &\n";

    print $configfh "seckey=$sk[$i]\n";
    print $configfh "listen-addr=tcp://*:$port\n";

    my $j = 0;
    foreach my $p (@pk) {
        my $portj = 12001 + $j;
        print $configfh "peer=tcp://127.0.0.1:$portj|$p\n";
        $j++;
    }

    print $configfh "\n";

    close $configfh;
}
print $scriptfh "\n";

close $scriptfh;


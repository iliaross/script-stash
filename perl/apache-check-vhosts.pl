#!/usr/bin/env perl
# apache-check-vhosts.pl (https://github.com/iliaross/script-stash)
# Copyright Ilia Ross <ilia@ross.gdn>
# Licensed under the MIT License
#
# Script to check Apache virtual host configurations by enabling them
# one by one and verifying that the Apache configuration remains valid
# and that the service can be reloaded successfully. If a site causes
# a failure, it is disabled again and reported at the end.

use strict;
use warnings;

# Return if no apache2ctl found
if (! -x '/usr/sbin/apache2ctl') {
	print STDERR "Error: apache2ctl command not found or not executable\n";
	exit 1;
	}

# Configuration
my $sites_available   = '/etc/apache2/sites-available';
my $sites_enabled_dir = '/etc/apache2/sites-enabled';
my %protected_sites   = map { $_ => 1 } qw(000-default default-ssl);

# Colors (disable with non-tty)
my $use_color = (-t STDOUT && !$ENV{NO_COLOR}) ? 1 : 0;
sub color
{
my ($c, $s) = @_;
return $s unless $use_color;
my %m = (reset => 0, bold => 1, dim => 2, red => 91, green => 92, yellow => 93,
         blue => 94, magenta => 95, cyan => 96, gray => 90);

"\e[$m{$c}m$s\e[0m";
}

# Symbols
my ($OK, $FAIL, $ARW) = ("✔", "✘", "→");

# Run quietly
sub run_quiet
{
my @cmd = @_;
my $q = join ' ', map { (my $s = $_) =~ s/'/'"'"'/g; "'$s'"} @cmd;
system('sh', '-c', "$q >/dev/null 2>&1") == 0;
}

# Wrappers
sub sh_ok     { system(@_) == 0 }
sub config_ok { run_quiet('apache2ctl', 'configtest') }
sub reload_ok { run_quiet('systemctl', 'reload', 'apache2') }
sub start_ok  { run_quiet('systemctl', 'start', 'apache2') }
sub is_active { run_quiet('systemctl', 'is-active', '--quiet', 'apache2') }

sub enable_site  { run_quiet('a2ensite', '--quiet',  $_[0]) }
sub disable_site { run_quiet('a2dissite', '--quiet', $_[0]) }

sub section
{
my ($title) = @_;
my $bar = '-' x (length($title) + 4);
print color('gray', $bar), "\n", color('bold', "| $title |"), "\n",
      color('gray', $bar), "\n";
}

# Gather sites
opendir(my $dh, $sites_available) or die "Cannot open $sites_available: $!\n";
my @all = sort map { (my $n = $_) =~ s/\.conf$//r }
	  grep { /\.conf$/ } readdir($dh);
closedir $dh;
my @candidates = grep { !$protected_sites{$_} } @all;

opendir(my $eh, $sites_enabled_dir) or
	die "Cannot open $sites_enabled_dir: $!\n";
my @enabled_now = map { (my $n = $_) =~ s/\.conf$//r }
	grep { /\.conf$/ } readdir($eh);
closedir $eh;
my %enabled = map { $_ => 1 } @enabled_now;

# Headers
section("Apache virtual host validator");
print color('dim',"Skipping  : "), join(', ', sort keys %protected_sites), "\n";
print color('dim',"Validating: "), (@candidates
	? join(', ', @candidates)
	: 'none'), "\n\n";

# Disable currently enabled (non-protected)
my @to_disable = grep { !$protected_sites{$_} && $enabled{$_} } @all;
if (@to_disable) {
	section("Disabling currently enabled non-protected sites");
	for (@to_disable) { disable_site($_); print "  $ARW $_ ",
			    color('yellow',"(disabled)\n"); }
	print "\n";
	}

# Baseline
section("Ensuring baseline (correct syntax and service running)");
die color('red',"Error: Config broken even with candidates disabled!")."\n"
	unless config_ok();
start_ok() unless is_active();
print color('green',"  $OK\n\n");

# Per-site enable
section("Enabling sites one by one");
my (@good, @bad);
my $pad = 0;
for (@candidates) {
    $pad = length($_) if length($_) > $pad
    }
$pad += 2;

SITE: for my $v (@candidates) {
	printf "  %s %-*s", color('cyan', $ARW), $pad, $v;

	enable_site($v) or do {
		print color('red'," $FAIL a2ensite\n"); push @bad, $v; next SITE;
		};

	unless (config_ok()) {
		print color('red'," $FAIL configtest\n");
		system('apache2ctl','configtest');
		disable_site($v);
		config_ok();
		push @bad, $v; next SITE;
		}

	if (is_active()) {
		unless (reload_ok()) {
			print color('red'," $FAIL reload\n");
			disable_site($v);
			config_ok();
			reload_ok() || start_ok();
			push @bad, $v; next SITE;
			}
		}
	else {
		unless (start_ok()) {
			print color('red'," $FAIL start\n");
			disable_site($v);
			config_ok();
			start_ok();
			push @bad, $v; next SITE;
			}
		}

	print color('green'," $OK\n");
	push @good, $v;
	}

# Summary
print "\n";
section("Summary");
print color('green',"Passed: "), (@good ? join(', ', @good) : 'none'), "\n";
print color('red',"Failed: "), (@bad ? join(', ', @bad) : 'none'), "\n";

exit(@bad ? 1 : 0);

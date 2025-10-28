#!/usr/bin/env perl
# net-ip-lookup.pl (https://github.com/iliaross/script-stash)
# Copyright Ilia Ross <ilia@ross.gdn>
# Licensed under the MIT License
#
# Script to lookup comprehensive network information about an IP address or
# hostname including geolocation, ISP, ASN, timezone. Performs network
# diagnostics (ping, traceroute, port scanning). Auto-detects your public IP if
# no argument provided. Use --quick to skip slow diagnostics.
#
# Usage: netinfo.pl [--quick] [IP|HOSTNAME]
# Examples:
#   net-ip-lookup.pl                               # Auto-detect your IP
#   net-ip-lookup.pl 8.8.8.8                       # Lookup IP
#   net-ip-lookup.pl google.com                    # Lookup hostname
#   net-ip-lookup.pl --quick 2001:4860:4860::8844  # Quick mode (skip diagnostics)

use strict;
use warnings;
use JSON::PP;
use LWP::UserAgent;
use LWP::Protocol::https;
use Socket;
use IO::Socket::IP;

# Configuration constants
use constant {
	HTTP_TIMEOUT     => 5,
	HTTP_MAX_RETRIES => 2,
	USER_AGENT       => 'curl/7.68.0',
	EXIT_SUCCESS     => 0,
	EXIT_ERROR       => 1,
	EXIT_INVALID_IP  => 2,
	};

# Signal handling
$SIG{INT}  = sub { print STDERR "\nInterrupted.\n"; exit 130; };
$SIG{TERM} = sub { print STDERR "\nTerminated.\n"; exit 143; };

# IP address validation (IPv4 and IPv6)
sub validate_ip
{
my ($ip) = @_;
# IPv4: 0-255.0-255.0-255.0-255
if ($ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/) {
	return 0 if grep { $_ > 255 } ($1, $2, $3, $4);
	return 1;
	}
# IPv6: simplified check
if ($ip =~ /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/) {
	return 1;
	}
return 0;
}

# Validate hostname (alphanumeric, hyphens, dots, no special chars)
sub validate_hostname
{
my ($hostname) = @_;
return 0 if $hostname =~ /[;&|`\$<>(){}[\]!*?~^'"\\]/;
return 0 if $hostname =~ /^\s*$/;     # Empty or whitespace
return 0 if length($hostname) > 253;  # Max hostname length
# A valid format consists of names separated by dots, with each label being 1-63
# characters long at most
return $hostname =~ /^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9._-]{0,61}[a-zA-Z0-9])?)*$/;
}

# Resolve hostname to IP address
sub resolve_hostname
{
my ($hostname) = @_;
my @ips;

# Try IPv4 first
my $packed_ip = gethostbyname($hostname);
if (defined $packed_ip) {
	my $ip = inet_ntoa($packed_ip);
	push @ips, $ip if $ip;
	}

# Try IPv6 if IPv4 failed
if (!@ips) {
	# Use getaddrinfo for IPv6
	eval {
		require Socket;
		my ($err, @res) = Socket::getaddrinfo($hostname, "", {
			family   => AF_INET6,
			socktype => SOCK_STREAM
			});
		if (!$err && @res) {
			for my $ai (@res) {
				my ($err, $ipaddr) =
					Socket::getnameinfo($ai->{addr},
					Socket::NI_NUMERICHOST,
					Socket::NIx_NOSERV);
				if (!$err && $ipaddr) {
					push @ips, $ipaddr;
					last;  # Take first IPv6
					}
				}
			}
		};
	}

return @ips;
}

# Get current public IP from reliable services
sub get_my_ip
{
my @services = (
	'https://api.ipify.org',
	'https://ifconfig.me/ip',
	'https://icanhazip.com',
	'https://ipinfo.io/ip',
	);

for my $service (@services) {
	my $content = http_get($service);
	if ($content) {
		chomp $content;
		$content =~ s/^\s+|\s+$//g;  # Trim whitespace
		return $content if (validate_ip($content));
		}
	}
return undef;
}

# Colors (disable with non-tty)
my $use_color = (-t STDOUT && !$ENV{NO_COLOR}) ? 1 : 0;
sub color
{
my ($c, $s) = @_;
return $s unless $use_color;
my %colors = (reset => 0, bold => 1, dim => 2, red => 91, green => 92,
	      yellow => 93, blue => 94, magenta => 95, cyan => 96, gray => 90);
return $s unless exists $colors{$c};
"\e[$colors{$c}m$s\e[0m";
}

# Symbols
my ($OK, $WARN) = ("✔", "⚠");

# Section header
sub section
{
my ($title) = @_;
my $bar = '-' x (length($title) + 4);
print "\n", color('gray', $bar), "\n", color('bold', "| $title |"),
      "\n", color('gray', $bar), "\n";
}

# Print labeled information
sub print_info
{
my ($label, $value, $indent) = @_;
$indent //= 2;
return unless defined $value;
return if $value eq 'null' || $value eq '' || $value eq 'false';
# Convert boolean true to readable format
$value = 'yes' if $value eq 'true'  || $value eq '1';
$value = 'no'  if $value eq 'false' || $value eq '0';
printf "%s%s %s\n", (' ' x $indent), color('dim', "$label:"), $value;
}

# Safe JSON decode with error handling
sub decode_json_safe
{
my ($json_text) = @_;
return undef unless defined $json_text && $json_text ne '';
# Remove BOM and whitespace
$json_text =~ s/^\s+//;
$json_text =~ s/\s+$//;
my $data;
eval {
	$data = JSON::PP->new->utf8->decode($json_text);
	};
if ($@) {
	warn "JSON decode error: $@\n" if $ENV{DEBUG};
	warn "Content: " . substr($json_text, 0, 200) . "...\n"
		if $ENV{DEBUG};
	return undef;
	}
return $data;
}

# HTTP GET with retry logic
sub http_get
{
my ($url, $retries) = @_;
$retries //= HTTP_MAX_RETRIES;

my $ua = LWP::UserAgent->new(
	timeout      => HTTP_TIMEOUT,
	max_redirect => 5,
	ssl_opts     => { verify_hostname => 0, SSL_verify_mode => 0 }
	);
$ua->agent('Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 '.
	   'Firefox/119.0');
$ua->default_header('Accept' => 'application/json, text/plain, */*');
$ua->default_header('Accept-Language' => 'en-US,en;q=0.9');
$ua->default_header('Accept-Encoding' => 'gzip, deflate');

for my $attempt (1 .. $retries + 1) {
	my $response = $ua->get($url);
	if ($response->is_success) {
		my $content = $response->decoded_content;
		warn "[HTTP] Success from $url (attempt $attempt)\n"
			if $ENV{DEBUG};
		warn "[HTTP] Content length: " . length($content) . " bytes\n"
			if $ENV{DEBUG};
		return $content;
		}
	warn "[HTTP] Attempt $attempt failed for $url: " .
	     $response->status_line . "\n" if $ENV{DEBUG};
	warn "[HTTP] Response content: " . 
	     substr($response->decoded_content, 0, 200) . "\n"
		if $ENV{DEBUG} && $response->decoded_content;
	sleep 1 if $attempt < $retries + 1;
	}
return undef;
}

# Get nested JSON value safely
sub jget
{
my ($data, @keys) = @_;
return undef unless defined $data && ref $data eq 'HASH';
for my $key (@keys) {
	return undef unless exists $data->{$key};
	$data = $data->{$key};
	}
return $data;
}

# Parse arguments
my $quick_mode = 0;
my $input;

for my $arg (@ARGV) {
	if ($arg eq '-q' || $arg eq '--quick') {
		$quick_mode = 1;
		}
	elsif ($arg =~ /^-/) {
		(my $script = $0) =~ s!.*/!!; $script =~ s!.*\\!!;
		print STDERR "Error: Unknown option '$arg'\n";
		print STDERR "Usage: $script [--quick] [IP|HOSTNAME]\n";
		exit EXIT_ERROR;
		}
	else {
		$input = $arg;
		}
	}


# Validate arguments and get IP
my $ip;
my $original_input = '';
my $resolved_from_hostname = 0;

if (!defined $input) {
	# No argument provided - get current public IP
	$ip = get_my_ip();
	if (!$ip) {
		print "No IP or hostname provided. Detecting your public IP ..\n";
		print ".. error: unable to detect your public IP address\n";
		exit EXIT_ERROR;
		}
	$original_input = 'auto-detected';
	}
elsif (validate_ip($input)) {
	# Valid IP provided
	$ip = $input;
	$original_input = $input;
	}
elsif (validate_hostname($input)) {
	# Resolve valid hostname
	$original_input = $input;
	my @resolved_ips = resolve_hostname($input);
	if (@resolved_ips) {
		$ip = $resolved_ips[0];
		$resolved_from_hostname = 1;
		}
	else {
		print "Resolving '$input' hostname ..\n";
		print ".. error: unable to resolve given hostname\n";
		exit EXIT_ERROR;
		}
	}
else {
	print "Error: Invalid IP address or hostname format\n";
	exit EXIT_INVALID_IP;
	}

# Print main header
my $header_text = 'Network Information Lookup';
my $header_bar = '=' x length($header_text);
print "\n", color('gray', $header_bar), "\n";
print color('bold', $header_text), "\n";
print color('gray', $header_bar), "\n\n";

# Display target
print color('bold', 'Target: '), color('yellow', $original_input);
if ($resolved_from_hostname) {
	print " → ", color('yellow', $ip);
	}
print "\n";

# Determine IP version
my $ip_version = ($ip =~ /:/) ? 'IPv6' : 'IPv4';

# Basic Information
section('BASIC INFORMATION');
print_info('IP Address', $ip);
print_info('IP Version', $ip_version);

# Reverse DNS lookup
my $reverse_dns = `dig +short -x $ip 2>/dev/null | head -1`;
chomp $reverse_dns if $reverse_dns;
print_info('Reverse DNS', $reverse_dns) if $reverse_dns;

# Query services in order of reliability and stop after first success
my $service_success = 0;
my @services = (
	{
	name => 'ipapi.co',
	code => sub {
		section('ipapi.co');
		my $url = "https://ipapi.co/$ip/json/";
		my $content = http_get($url);
		if ($content) {
			my $data = decode_json_safe($content);
			if ($data && ref $data eq 'HASH' &&
			    !jget($data, 'error')) {
				print_info('IP', jget($data, 'ip'));
				print_info('Version', jget($data, 'version'));
				print_info('City', jget($data, 'city'));
				print_info('Region', jget($data, 'region'));
				print_info('Region Code', jget($data,
					'region_code'));
				print_info('Country', jget($data,
					'country_name'));
				print_info('Country Code', jget($data,
					'country_code'));
				print_info('Continent Code', jget($data,
					'continent_code'));
				my $lat = jget($data, 'latitude');
				my $lon = jget($data, 'longitude');
				print_info('Coordinates', "$lat,$lon")
					if (defined $lat && defined $lon);
				print_info('Postal Code', jget($data,
					'postal'));
				print_info('Timezone', jget($data,
					'timezone'));
				print_info('UTC Offset', jget($data,
					'utc_offset'));
				print_info('Calling Code', jget($data,
					'country_calling_code'));
				print_info('Currency', jget($data, 'currency'));
				print_info('Languages', jget($data,
					'languages'));
				print_info('ASN', jget($data, 'asn'));
				print_info('Organization', jget($data, 'org'));
				return 1;  # Success
				}
			else {
				my $err = jget($data, 'reason') ||
					  'Unable to parse response';
				print "  ", color('yellow', "$WARN $err"), "\n";
				}
			}
		else {
			print "  ", color('yellow',
				"$WARN Service unavailable"), "\n";
			}
		return 0;  # Failed
		}
	},
	{
	name => 'ipinfo.io',
	code => sub {
		section('ipinfo.io');
		my $url = "https://ipinfo.io/$ip/json";
		my $content = http_get($url);
		if ($content) {
			my $data = decode_json_safe($content);
			if ($data && ref $data eq 'HASH') {
				print_info('IP', jget($data, 'ip'));
				print_info('Hostname', jget($data, 'hostname'));
				print_info('City', jget($data, 'city'));
				print_info('Region', jget($data, 'region'));
				print_info('Country', jget($data, 'country'));
				print_info('Location', jget($data, 'loc'));
				print_info('Organization', jget($data, 'org'));
				print_info('Postal Code', jget($data,
					'postal'));
				print_info('Timezone', jget($data, 'timezone'));
				
				# Privacy detection
				my $privacy = jget($data, 'privacy');
				if ($privacy && ref $privacy eq 'HASH') {
					print_info('VPN', jget($privacy,
						'vpn'));
					print_info('Proxy', jget($privacy,
						'proxy'));
					print_info('Tor', jget($privacy,
						'tor'));
					print_info('Relay', jget($privacy,
						'relay'));
					print_info('Hosting', jget($privacy,
						'hosting'));
					}
				
				# ASN information
				my $asn = jget($data, 'asn');
				if ($asn && ref $asn eq 'HASH') {
					print_info('ASN', jget($asn,
						'asn'));
					print_info('ASN Name', jget($asn,
						'name'));
					print_info('ASN Domain', jget($asn,
						'domain'));
					print_info('ASN Route', jget($asn,
						'route'));
					print_info('ASN Type', jget($asn,
						'type'));
					}
				return 1;  # Success
				}
			else {
				print "  ", color('yellow',
					"$WARN Unable to parse response"), "\n";
				}
			}
		else {
			print "  ", color('yellow',
				"$WARN Service unavailable"), "\n";
			}
		return 0;  # Failed
		}
	},
	{
	name => 'ip-api.com',
	code => sub {
		section('ip-api.com');
		my $url = "http://ip-api.com/json/$ip?fields=status,message,continent," .
			"continentCode,country,countryCode,region,regionName,city," .
			"district,zip,lat,lon,timezone,offset,currency,isp,org,as," .
			"asname,reverse,mobile,proxy,hosting,query";
		my $content = http_get($url);
		if ($content) {
			my $data = decode_json_safe($content);
			if ($data && ref $data eq 'HASH' &&
			    jget($data, 'status') eq 'success') {
				print_info('IP', jget($data, 'query'));
				my $cont = jget($data, 'continent');
				my $cont_code = jget($data, 'continentCode');
				print_info('Continent', "$cont ($cont_code)")
					if (defined $cont && defined $cont_code);
				my $country = jget($data, 'country');
				my $country_code = jget($data, 'countryCode');
				print_info('Country', "$country ($country_code)")
					if (defined $country && defined $country_code);
				my $region_name = jget($data, 'regionName');
				my $region = jget($data, 'region');
				print_info('Region', "$region_name ($region)")
					if (defined $region_name && defined $region);
				print_info('City', jget($data, 'city'));
				print_info('District', jget($data, 'district'));
				print_info('ZIP Code', jget($data, 'zip'));
				my $lat = jget($data, 'lat');
				my $lon = jget($data, 'lon');
				print_info('Coordinates', "$lat,$lon")
					if (defined $lat && defined $lon);
				print_info('Timezone', jget($data, 'timezone'));
				print_info('UTC Offset', jget($data, 'offset'));
				print_info('Currency', jget($data, 'currency'));
				print_info('ISP', jget($data, 'isp'));
				print_info('Organization', jget($data, 'org'));
				print_info('AS', jget($data, 'as'));
				print_info('AS Name', jget($data, 'asname'));
				print_info('Reverse DNS', jget($data, 'reverse'));
				print_info('Mobile', jget($data, 'mobile'));
				print_info('Proxy', jget($data, 'proxy'));
				print_info('Hosting', jget($data, 'hosting'));
				return 1;  # Success
				}
			elsif ($data && ref $data eq 'HASH') {
				my $msg = jget($data, 'message') ||
					  'Unknown error';
				print "  ", color('red', "Error: $msg"), "\n";
				}
			else {
				print "  ", color('yellow',
					"$WARN Unable to parse response"), "\n";
				}
			}
		else {
			print "  ", color('yellow',
				"$WARN Service unavailable"), "\n";
			}
		return 0;  # Failed
		}
	},
	{
	name => 'ifconfig.co',
	code => sub {
		section('ifconfig.co');
		my $url = "https://ifconfig.co/json?ip=$ip";
		my $content = http_get($url);
		if ($content) {
			my $data = decode_json_safe($content);
			if ($data && ref $data eq 'HASH') {
				print_info('IP', jget($data, 'ip'));
				print_info('IP Decimal', jget($data,
					'ip_decimal'));
				print_info('Country', jget($data,
					'country'));
				print_info('Country ISO', jget($data,
					'country_iso'));
				print_info('Country EU', jget($data,
					'country_eu'));
				print_info('Region Name', jget($data,
					'region_name'));
				print_info('Region Code', jget($data,
					'region_code'));
				print_info('City', jget($data, 'city'));
				my $lat = jget($data, 'latitude');
				my $lon = jget($data, 'longitude');
				print_info('Coordinates', "$lat,$lon")
					if (defined $lat && defined $lon);
				print_info('Timezone', jget($data,
					'time_zone'));
				print_info('ASN', jget($data, 'asn'));
				print_info('ASN Organization', jget($data,
					'asn_org'));
				return 1;  # Success
				}
			else {
				print "  ", color('yellow',
					"$WARN Unable to parse response"), "\n";
				}
			}
		else {
			print "  ", color('yellow',
				"$WARN Service unavailable"), "\n";
			}
		return 0;  # Failed
		}
	},
	);

# Try services in order until one succeeds
for my $service (@services) {
	if ($service->{code}->()) {
		$service_success = 1;
		last;  # Stop after first success
		}
	}

if (!$service_success) {
	print "\n", color('red', 'Error: All IP lookup services failed'), "\n";
	}

# Network diagnostics
section('NETWORK DIAGNOSTICS');

# IP type classification
my $ip_type = 'Public';
if ($ip =~ /^127\./) {
	$ip_type = 'Loopback';
	}
elsif ($ip =~ /^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\./) {
	$ip_type = 'Private (RFC1918)';
	}
elsif ($ip =~ /^169\.254\./) {
	$ip_type = 'Link-Local (APIPA)';
	}
elsif ($ip =~ /^(22[4-9]|23[0-9])\./) {
	$ip_type = 'Multicast';
	}
elsif ($ip =~ /^::1$|^fe80:/i) {
	$ip_type = 'IPv6 Link-Local/Loopback';
	}
elsif ($ip =~ /^fc00:|^fd00:/i) {
	$ip_type = 'IPv6 Private (ULA)';
	}
print_info('IP Type', $ip_type);

# Ping test with detailed statistics
print "\n", color('dim', 'Ping Test:'), "\n";
my $ping_cmd = ($ip_version eq 'IPv6')
	? $^O eq 'darwin'
		? "ping6 -c 3 $ip"
		: "ping6 -c 3 -W 2 $ip"
	: "ping -c 3 -W 2 $ip";
my $ping_result = `$ping_cmd 2>&1`;
if ($? == 0 && $ping_result) {
	# Extract statistics and handle multiple ping output formats
	my ($sent, $received, $loss);
	if ($ping_result =~ /(\d+) packets transmitted.*?(\d+)(?: packets)? received/) {
		($sent, $received) = ($1, $2);
		$loss = $sent > 0 ? (($sent - $received) / $sent) * 100 : 100;
		print "  ", color('green', $OK), " Host is reachable\n";
		printf "  Packets: %d sent, %d received (%.0f%% loss)\n",
		       $sent, $received, $loss;
		}
	# Extract stats
	if ($ping_result =~ m{(?:rtt|round-trip) min/avg/max(?:/mdev|/std-?dev)? = ([\d.]+)/([\d.]+)/([\d.]+)(?:/([\d.]+))? ms}) {
		my ($min, $avg, $max, $stddev) = ($1, $2, $3, $4 || 0);
		printf "  Latency: min=%.1fms, avg=%.1fms, max=%.1fms" .
		       ($stddev ? ", stddev=%.1fms\n" : "\n"),
		       $min, $avg, $max, $stddev;
		}
	}
else {
	print "  ", color('yellow', "$WARN Not responding"),
	      " (ICMP may be blocked)\n";
	}

# Skip traceroute and port checks in quick mode
if (!$quick_mode) {
	print "\n", color('dim', 'Traceroute (max 15 hops):'), "\n";
	my $traceroute_cmd;
	if ($ip_version eq 'IPv6') {
		$traceroute_cmd = ($^O eq 'darwin')
			? "traceroute6 -m 15 -w 2 $ip"
			: "traceroute6 -m 15 -w 2 -q 1 $ip";
		}
	else {
		$traceroute_cmd = ($^O eq 'darwin')
			? "traceroute -m 15 -w 2 $ip"
			: "traceroute -m 15 -w 2 -q 1 $ip";
		}
	my $traceroute = `$traceroute_cmd 2>/dev/null`;
	if ($? == 0 && $traceroute && $traceroute !~ /command not found/i) {
		my @hops = split /\n/, $traceroute;
		my $hop_count = 0;
		for my $hop (@hops) {
			# Skip header line
			next if $hop =~ /^traceroute to/i;
			$hop_count++;
			last if $hop_count > 15;
			# Clean up and format the hop
			$hop =~ s/^\s+//;
			if ($hop =~ /^\d+\s+(.+)$/) {
				my $hop_info = $1;
				# Truncate if too long
				if (length($hop_info) > 65) {
					$hop_info = substr($hop_info, 0, 65) . '...';
					}
				print "  $hop_info\n";
				}
			}
		if ($hop_count == 0) {
			print "  ", color('yellow',
				"$WARN No route information available"),
			      "\n";
			}
		}
	else {
		print "  ", color('yellow', "$WARN Traceroute failed"),
		      " (traceroute not installed)\n";
		}
	
	# Port connectivity check
	print "\n", color('dim', 'Port Connectivity:'), "\n";
	my %ports = (
		# Web Services
		'80'    => 'HTTP',
		'443'   => 'HTTPS',
		'8080'  => 'HTTP-Alt',
		'8443'  => 'HTTPS-Alt/Plesk',
		# Control Panels
		'10000' => 'Webmin',
		'2082'  => 'cPanel',
		'2083'  => 'cPanel-SSL',
		'2086'  => 'WHM',
		'2087'  => 'WHM-SSL',
		'9090'  => 'Cockpit',
		# Remote Access
		'22'    => 'SSH/SFTP',
		'3389'  => 'RDP',
		'5900'  => 'VNC',
		# File Transfer
		'21'    => 'FTP',
		'69'    => 'TFTP',
		'989'   => 'FTPS-Data',
		'990'   => 'FTPS',
		# Email
		'25'    => 'SMTP',
		'110'   => 'POP3',
		'143'   => 'IMAP',
		'465'   => 'SMTPS',
		'587'   => 'SMTP-Sub',
		'993'   => 'IMAPS',
		'995'   => 'POP3S',
		# Database
		'3306'  => 'MySQL',
		'5432'  => 'PostgreSQL',
		'1433'  => 'MSSQL',
		'27017' => 'MongoDB',
		'6379'  => 'Redis',
		# Messaging
		'5222'  => 'XMPP-Client',
		'5269'  => 'XMPP-Server',
		'1883'  => 'MQTT',
		# Other
		'53'    => 'DNS',
		'123'   => 'NTP',
		'161'   => 'SNMP',
		'162'   => 'SNMP-Trap',
		'389'   => 'LDAP',
		'636'   => 'LDAPS',
		'1194'  => 'OpenVPN',
		'1723'  => 'PPTP',
		'3000'  => 'Dev-Server',
		'5000'  => 'Synology-DSM',
		'5901'  => 'VNC-Alt',
		'8081'  => 'Proxy-Alt',
		'9091'  => 'Transmission',
		'10050' => 'Zabbix-Agent',
		'11211' => 'Memcached',
		'27015' => 'Steam-Game',
		);
	
	my @open_ports;
	my $check_count = 0;
	for my $port (sort { $a <=> $b } keys %ports) {
		$check_count++;
		# Show progress for long checks (every 10 ports)
		if ($check_count % 10 == 0 && $ENV{DEBUG}) {
			warn "  [DEBUG] Checked $check_count ports...\n";
			}
		my $sock = IO::Socket::IP->new(
			PeerHost => $ip,
			PeerPort => $port,
			Type     => Socket::SOCK_STREAM(),
			Timeout  => 1,
			);
		if ($sock) {
			push @open_ports, "$port/" . $ports{$port};
			close($sock);
			}
		}
	
	if (@open_ports) {
		# Group ports for better readability with line wrapping
		my $line = "  " . color('green', $OK) . " Open: ";
		my $current_length = length("  Open: ");
		for my $i (0 .. $#open_ports) {
			my $port = $open_ports[$i];
			my $separator = ($i < $#open_ports) ? ', ' : '';
			# Wrap to next line if too long (60 chars)
			if ($current_length + length($port) + length($separator) > 60) {
				print $line, "\n";
				$line = "          ";  # 10 spaces for indent
				$current_length = 10;
				}
			$line .= $port . $separator;
			$current_length += length($port) + length($separator);
			}
		print $line, "\n";
		}
	else {
		print "  ", color('dim', 'No common ports responding'), "\n";
		}
	}
else {
	print "\n", color('dim',
		'Traceroute and port checks skipped in quick mode'), "\n";
	}

# Summary
section('LOOKUP COMPLETE');
print color('green', $OK), " Information gathered for: ",
      color('yellow', $original_input);
if ($resolved_from_hostname) {
	print " (", color('yellow', $ip), ")";
	}
print "\n\n";

exit EXIT_SUCCESS;

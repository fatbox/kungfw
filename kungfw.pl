#!/usr/bin/perl -w
use strict;
#
# FatBox Inc. - KungFw
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met: 
#
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in
#   the documentation and/or other materials provided with the
#   distribution.
# * Neither the name of the KungFw nor the names of its contributors
#   may be used to endorse or promote products derived from this
#   software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

=head1 NAME

KungFw 2 - iptables ruleset generator

=head1 DESCRIPTION

This is an iptables ruleset generator built with security in mind for
building rulesets for routed & bridging firewalls as well as
individual hosts.

=head1 SYNOPSIS

Edit kungfw.yml to your liking, then run C<kungfw.pl -d show> to view
the generated ruleset with full debugging of the generation process.

C<kungfw.pl start> will load the generated ruleset

C<kungfw.pl stop> will unload the generated ruleset and set everything
back to accept by default.

=cut

use Data::Dumper;
use File::Glob ':globally';
use YAML;
use Net::IP;
use FindBin qw($Bin);

use vars qw($config $debug $command $out_file_opened $iptables $ebtables $ip $grep $i $opt);

# set defaults
$debug = 0;
$config = "$Bin/kungfw.yml";
$command = "";

# process command line
for ($i = 0; $i < @ARGV; $i++) {
	if (substr($ARGV[$i],0,1) eq '-') {
		$opt = substr($ARGV[$i],1,1);
		if ($opt eq 'c') {
			$config = $ARGV[++$i];
		} elsif ($opt eq 'd') {
			$debug = 1;
		} elsif ($opt eq 'h') {
			help(); 
		} else {
			help("Unknown option: $opt");
		}
	} elsif (($ARGV[$i] eq "start") or ($ARGV[$i] eq "stop") or ($ARGV[$i] eq "show")) {
		$command = $ARGV[$i];
	} else {
		help("Unknown command: $ARGV[$i]");
	}
}

help() if ($command eq '');

# load the config
debug("Loading config file: $config");
($config) = YAML::LoadFile($config) or die;

# sanity check
sanity();

# begin the temp file
begin_file();

# set sysctl config through /proc/sys interface
set_sysctl();

# init iptables
init_iptables();

# apply and exit if we're called with stop
if ($command eq 'stop') {
	apply();
	exit;
}

# create some default chains
init_chains();

# drop tcp scan attempts
drop_tcp_scans();

# allow loopback traffic
outline("# allow loopback traffic");
iptables("-A INPUT -i " . $config->{'loopback'} . " -j ACCEPT");
iptables("-A OUTPUT -o " . $config->{'loopback'} . " -j ACCEPT");
outline();

# process broadcast traffic settings
process_broadcasts();

# process multicast
process_multicast();

# process banned traffic
drop_banned();

# process icmp traffic
allow_icmp();

# process localnets
process_localnets();

# process custom rules
process_custom();

# process local services
process_local();

# process targets
process_targets();

# final targets
outline("# log and drop everything else");
iptables("", 'LOGDROP', qw(INPUT OUTPUT FORWARD));
outline("\n### EOF");

# process command
if ($command eq 'show') {
	close(OUT);
	open(SHOW, "/tmp/kungfw.$$") or die "Couldn't read /tmp/kungfw.$$: $!";
	while (<SHOW>) {
		print $_;
	}
	close(SHOW);
}
apply() if ($command eq 'start');

# we're outta here
cleanup();
exit;

#######################################################################

=head1 PROGRAM DOCUMENTATION

The following documentation is not of any interest to an end user. It
has been added to detail the development of the rule compiler that is
kungfw.

If you're still interested, read on...

=over 4

=cut

=item I<help()>

Displays a help message

=cut

sub help {
	my $msg = shift;
	print $msg . "\n\n" if ($msg);

	die("Usage: kungfw.pl [-c <config>] [-d] [-h] [start|stop|show]\n");
}

=item I<debug($msg)>

Prints $msg if $debug is true (1)

=cut 

sub debug {
	return unless $debug == 1;
	my $msg = shift;
	print $msg . "\n";
}

=item I<apply()>

Loads the generated ruleset

=cut

sub apply {
	close(OUT);
	open(START, "/bin/sh /tmp/kungfw.$$ 2>&1 |") or die "Couldn't spawn /bin/sh /tmp/kungfw.$$: $!";
	while (<START>) {
		print $_;
	}
	close(START);
}

=item I<begin_file()>

Adds a header to the temp file that holds the generated ruleset

=cut

sub begin_file {
	outline("#\n# KungFw - Auto-generated file\n# generated " . localtime() . "\n#\n");
}

sub mode {
	my ($mode) = @_;
	return 1 if ($config->{'mode'} eq $mode);
}

=item I<sanity()>

Sanity checking

 - Locate binaries
 - Check interfaces
 - Check networks
 - Setup defaults

=cut

sub sanity {
	local $_;

	debug("Sanity checking");

	# get our required binaries
	$iptables = find_bin("iptables", "/sbin/iptables");
	debug(" - iptables: $iptables");
	$ip = find_bin("ip", "/bin/ip");
	debug(" - ip: $ip");
	$grep = find_bin("grep", "/bin/grep");
	debug(" - grep: $grep");

	# check the loopback
	$config->{'loopback'} = "lo" unless ($config->{'loopback'});
	check_interface($config->{'loopback'});
	die "ERROR: something failed checking the loopback interface (" . $config->{'loopback'} . ")" unless ($config->{'interfaces'}->{$config->{'loopback'}});

	# check the bridge
	if (mode('bridge')) {
		$config->{'bridge'} = "br0" unless ($config->{'bridge'});
		check_interface($config->{'bridge'});
		die "ERROR: something failed checking the bridge interface (" . $config->{'bridge'} . ")" unless ($config->{'interfaces'}->{$config->{'bridge'}});
	}

	# check the outside & inside
	$config->{'outside'} = "eth0" unless ($config->{'outside'});
	$config->{'inside'}  = "eth1" unless ($config->{'inside'});
	check_interface($config->{'outside'});
	check_interface($config->{'inside'}) unless (mode('host'));
	if (mode('bridge')) {
		die "ERROR: the interface " . $config->{'outside'} . " is listed as the outside bridge member but it has an IP address assigned!" if ($config->{'interfaces'}->{$config->{'outside'}});
		die "ERROR: the interface " . $config->{'inside'} . " is listed as the inside bridge member but it has an IP address assigned!" if ($config->{'interfaces'}->{$config->{'inside'}});
	}

	# make sure there is at least one local network defined
	if (!mode('host')) {
		die "ERROR: you must define at least one localnets entry" unless config_is_array($config->{'localnets'});
		debug("Found localnets");
		if ($debug == 1) {
			foreach (@{$config->{'localnets'}}) {
				debug(" - $_");
			}
		}
	}

	# set some defaults
	$config->{'privports'} = "0:1023";
	$config->{'unprivports'} = "1024:65535";
	$config->{'traceroute_srcports'} = "32769:65535";
	$config->{'traceroute_dstports'} = "33434:33523";
	$config->{'ssh_unprivports'} = "513:1023";
	$config->{'anywhere'} = "0/0";
}

=item I<find_bin($name, $bin)>

Helper function to locate a binary, a default can be passed as the second argument

=cut

sub find_bin {
	my ($name, $bin) = @_;
	if ( ! -x $bin ) {
		open(WH, "/bin/which $name 2>/dev/null |") or die "Couldn't spawn which: $!";
		while (<WH>) {
			chomp;
			$bin = $_;
		}
		close(WH);
		die("Cannot find $name binary. Is it in your path?") unless ( -x $bin );
	}
	return $bin;
}

=item I<check_interface($if)>

Gets, and stores, the ip address, netmask & broadcast of the specified interface

=cut

sub check_interface {
	my $if = shift;
	local $_;
	use vars qw($addr $mask $brd);

	debug("Checking interface: $if");

	open(IP, "$ip addr show $if 2>&1 |") or die "Could't spawn $ip: $!";
	while (<IP>) {
		die "ERROR: The interface $if does not exist. Check your config." if (/does not exist/);
		next unless (/inet ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\/([0-9]{1,2})(?: brd ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}))?/);
		$addr = $1;
		$mask = $2;
		$brd  = $3 if ($3);
		next if (/secondary/);
		$config->{'interfaces'}->{$if}->{'addr'} = $addr;
		$config->{'interfaces'}->{$if}->{'mask'} = $mask if ($mask);
		$config->{'interfaces'}->{$if}->{'brd'}	= $brd if ($brd);
		debug(" - addr: $addr");
		debug(" - mask: $mask") if $mask;
		debug(" - brd: $brd") if $brd;
		last;
	}
	close(IP);
}

=item I<config_is_array($ref)>

Returns true (1) if the reference passed is an array and has at least 1 item

=cut

sub config_is_array {
	my $ref = shift;
	return 1 if (($ref) and (ref($ref) eq 'ARRAY') and (@{$ref} > 0));
}

=item I<config_is_hash($ref)>

Returns true (1) if the reference passed is an hash

=cut

sub config_is_hash {
	my $ref = shift;
	return 1 if (($ref) and (ref($ref) eq 'HASH'));
}

=item I<cleanup()>

Removes the temp file holding the generated ruleset

=cut

sub cleanup {
	unlink "/tmp/kungfw.$$" if ( -f "/tmp/kungfw.$$" );
}

=item I<check_out_file()>

Makes sure the temporary file is ready for writing

=cut

sub check_out_file {
	if (!$out_file_opened) {
		open(OUT, ">/tmp/kungfw.$$") or die("Failed to open /tmp/kungfw.$$ for writing: $!");
		$out_file_opened = 1;
	}
}

=item I<outline($val)>

Prints $val with a newline to the temporary file

=cut

sub outline {
	my ($val) = @_;
	$val = "" unless ($val);

	check_out_file();
	print OUT "$val\n";
}

sub sysctl {
	my ($file, $val) = @_;

	check_out_file();
	debug("sysctl: $file=$val");
	print OUT "echo $val > /proc/sys/$file\n";
}

sub iptables {
	my ($rule, $chainjump, @chains) = @_;
	check_out_file();
	if (@chains > 0) {
		foreach my $chain (@chains) {
			print OUT "$iptables -A $chain $rule" . ($chainjump ? " -j " . $chain . $chainjump : "") . "\n";
		}
	} else {
		print OUT "$iptables $rule\n";
	}
}

sub set_sysctl {
	outline("# set sysctl values");

	### set some sysctl values
	# forward traffic
	sysctl("net/ipv4/ip_forward", "1");

	# respond to pings 
	sysctl("net/ipv4/icmp_echo_ignore_all", "0");

	# do not respond to icmp broadcasts
	sysctl("net/ipv4/icmp_echo_ignore_broadcasts", "1");

	my @conf_ifs = </proc/sys/net/ipv4/conf/*>;
	foreach (@conf_ifs) {
		s#/proc/sys/##;

		# do not accept source routed packets
		sysctl("$_/accept_source_route", "0");

		# do not accept icmp redirects
		sysctl("$_/accept_redirects", "0");

		# do no send icmp redirects
		sysctl("$_/send_redirects", "0");

		# drop spoofed packets coming in one interface out another
		sysctl("$_/rp_filter", "1");

		# log packets with impossible addresses
		sysctl("$_/log_martians", "1");
	}
	undef @conf_ifs;

	# increase the net filter tcp timeout to 2 minutes (default is 1 minute)
	# gets rid of dropped tcp packet out with ACK PSH FIN set
	sysctl("net/ipv4/netfilter/ip_conntrack_tcp_timeout_close_wait", "120");

	# call arptables & iptables (with vlan tags) for bridged traffic
	if (mode('bridge')) {
		sysctl("net/bridge/bridge-nf-call-arptables", "1");
		sysctl("net/bridge/bridge-nf-call-iptables", "1");
		sysctl("net/bridge/bridge-nf-filter-vlan-tagged", "1");
	}

	outline();
}

sub init_iptables {
	outline("# initialize iptables");

	debug("Initializing iptables. Flush, remove & zero");
	# flush, remove & zero
	iptables("-F");
	iptables("-F -t nat");
	iptables("-F -t mangle");
	iptables("-X");
	iptables("-X -t nat");
	iptables("-X -t mangle");
	iptables("-Z");

	# default to drop
	iptables("-P INPUT ACCEPT");
	iptables("-P OUTPUT ACCEPT");
	iptables("-P FORWARD ACCEPT");

	outline();
}

sub init_chains {
	outline("# create chains we will jump to so we can log packets");

	use vars qw($i $chain);

	# create 5 chains that will be jumped to for droping & rejecting packets
	# also when there is a possible scan (xmas / null packets)
	# also when there is a banned ip
	my @names = qw(LOGDROP LOGREJECT SCANDROP BANNED);
	my @jumps = qw(DROP REJECT DROP DROP);
	my @types = ("DROP %s", "REJECT %s", "%s SCAN", "BANNED %s");
	my @proto = qw(tcp udp icmp frag);
	my $cmd	 = "";

	foreach $chain (qw(INPUT OUTPUT FORWARD)) {
		for ($i = 0; $i < @jumps; $i++) {
			debug("Building $chain$names[$i] chain");
			iptables("-N $chain" . $names[$i]);
			foreach (@proto) {
				if (/frag/) {
					$cmd = "-f";
				} else {
					$cmd = "-p " . $_;
				}
				iptables("-A $chain" . $names[$i] . " $cmd -m limit --limit 1/s -j LOG --log-prefix \"[$chain " . sprintf($types[$i], uc($_)) . "] \" --log-level=info");
			}
			iptables("-A $chain" . $names[$i] . " -j " . $jumps[$i]);
		}
	}
	undef @names;
	undef @jumps;
	undef @types;
	undef @proto;
	undef $cmd;

	outline();
}

=item I<process_multicast()>

Allows multicast traffic if set to yes.

TODO: make this more configurable

=cut

sub process_multicast {
	return unless (($config->{'multicast'}) and ($config->{'multicast'} eq 'yes'));
	outline("# multicast traffic");
	iptables("-d 224.0.0.0/4 -j ACCEPT", "", qw(INPUT OUTPUT FORWARD));
	outline();
}


sub process_broadcasts {
	use vars qw($rule $rules $jump $tempref $chain $type @ifs);

	outline("# broadcast traffic");

	if (ref($config->{'broadcasts'}) ne 'HASH') {
		$tempref->{'input'}->{'directed'} = $tempref->{'input'}->{'limited'} = $tempref->{'forward'}->{'directed'} = $tempref->{'forward'}->{'limited'} = 'no';
		$config->{'broadcasts'} = $tempref;
	}

	if (mode('bridge')) {
		@ifs = ($config->{'bridge'});
	} else {
		@ifs = keys %{$config->{'interfaces'}};
	}

	foreach $chain (qw(input output forward)) {
		undef $tempref;
		if (ref($config->{'broadcasts'}->{$chain}) ne 'HASH') {
			$tempref->{'directed'} = $tempref->{'limited'} = (($config->{'broadcasts'}->{$chain}) and ($config->{'broadcasts'}->{$chain} eq 'yes') ? 'yes' : 'no');
			$config->{'broadcasts'}->{$chain} = $tempref;
		}

		foreach $type (qw(directed limited)) {
			undef $tempref;
			if (($config->{'broadcasts'}->{$chain}->{$type}) and ($config->{'broadcasts'}->{$chain}->{$type} ne 'yes')) {
				next;
			}

			foreach (@ifs) {
				next if (/^lo/);
				undef $tempref;
				if ($type eq 'directed') {
					$tempref->{'dest'} = $config->{'interfaces'}->{$_}->{'brd'};
				} else {
					$tempref->{'dest'} = "255.255.255.255";
				}
				$tempref->{'chain'} = uc($chain);
				$tempref->{'int'} = $_;
				push @{$rules}, $tempref;
			}
		}
	}

	foreach (@{$rules}) {
		$rule  = "-A " . $_->{'chain'} . " -d " .$_->{'dest'};
		if ($_->{'int'}) {
			if ($_->{'chain'} eq 'INPUT') {
				$rule .= " -i " . $_->{'int'};
			} elsif ($_->{'chain'} eq 'OUTPUT') {
				$rule .= " -o " . $_->{'int'};
			} elsif ($_->{'chain'} eq 'FORWARD') {
				if ($config->{'mode'} eq 'bridge') {
					$rule .= " -m physdev --physdev-in " . $_->{'int'};
				} else {
					$rule .= " -i " . $_->{'int'};
				}
			}
		}
		iptables("$rule -j ACCEPT");
	}

	outline();
}

sub drop_tcp_scans {
	outline("# drop bogus tcp flags (scans)");

	my @flags = (
		"ALL NONE",		# all bits are cleared
		"SYN,FIN SYN,FIN",	# syn & fin are both set
		"SYN,RST SYN,RST",	# syn & rst are both set
		"FIN,RST FIN,RST", 	# fin & rst are both set
		"ACK,FIN FIN",		# only fin without the ack
		"ACK,PSH PSH",		# only psh without the ack
		"ACK,URG URG"		# only urg without the ack
	);

	foreach my $flag (@flags) {
		debug("Adding TCP flag check: $flag");
		iptables("-p tcp --tcp-flags $flag", 'SCANDROP', qw(INPUT FORWARD));
	}

	outline();
}

sub drop_banned {
	return unless ($config->{'banned'});

	outline("# drop banned hosts");

	foreach (@{$config->{'banned'}}) {
		debug("Banned: $_");
		iptables("-s $_", 'BANNED', qw(INPUT OUTPUT FORWARD));
		iptables("-d $_", 'BANNED', qw(INPUT OUTPUT FORWARD));
	}

	outline();
}

sub allow_icmp {
	# icmp allowed:
	# 0 - echo reply
	# 3 - destination unreachable / service unavailable
	# 4 - source quench
	# 8 - echo request
	# 11 - time exceeded
	# 12 - parameter problem
	my @types = qw(0 3 4 8 11 12);

	debug("Allowing ICMP");
	outline("# allow certain icmp");

	foreach my $type (@types) {
		iptables("-p icmp --icmp-type $type -j ACCEPT", 0, qw(INPUT OUTPUT FORWARD));
	}

	# one special case
	iptables("-p icmp --icmp-type fragmentation-needed -j ACCEPT", 0, qw(OUTPUT FORWARD));

	outline();
}

sub process_localnets {
  return unless config_is_array($config->{'localnets'});

  outline("# localnets");

  # on the inside interface all local nets are allowed to forward between each other
  foreach my $net1 (@{$config->{'localnets'}}) {
  	foreach my $net2 (@{$config->{'localnets'}}) {
		next if ($net1 eq $net2);
		iptables("-A FORWARD -i " . $config->{'inside'} . " -o " . $config->{'inside'} . " -s $net1 -d $net2 -j ACCEPT");
	}
  }

  outline();
}

sub process_custom {
	return unless config_is_array($config->{'custom'});

	outline("# custom rules");
	foreach (@{$config->{'custom'}}) {
		debug("Custom: $_");
		iptables($_);
	}
	outline();
}

sub process_local {
	process_hosts('local');
}

sub process_targets {
	process_hosts('targets');
}

sub process_hosts {
	my ($type) = @_;
	return unless config_is_hash($config->{$type});
	use vars qw(@targets $key $ips $target $svc $tun $addr);

	foreach $key (keys %{$config->{$type}}) {
		debug("Processing target definition: $key");
		@targets = split(/\|/, $key);
		foreach (@targets) {
			s/^\s*//g;
			s/\s*$//g;
			debug(" - $_");
			undef $ips;
			$ips = new Net::IP($_) or die "Invalid target definition $_: $!";

			do {
				$target = $ips->ip();
				debug("Processing $type: $target");

				if (config_is_hash($config->{$type}->{$key}->{'services'})) {
					foreach $svc (keys %{$config->{$type}->{$key}->{'services'}}) {
						if ($svc eq 'decorate') {
							foreach $svc (@{$config->{$type}->{$key}->{'services'}->{'decorate'}}) {
								if ($config->{'decorations'}->{$svc}) {
									debug("Processing $type $target service decoration: $svc");
									if ($type eq 'targets') {
										process_target_service($svc, $target, $config->{'decorations'}->{$svc});
									} elsif ($type eq 'local') {
										process_local_service($svc, $target, $config->{'decorations'}->{$svc});
									} else {
										print "Unknown type $type -- please fix this...\n";
									}
								} else {
									print "WARNING: invalid decoration: $svc\n";
								}
							}

							next;
						}

						debug("Processing $type $target service: $svc");
						if ($type eq 'targets') {
							process_target_service($svc, $target, $config->{$type}->{$key}->{'services'}->{$svc});
						} elsif ($type eq 'local') {
							process_local_service($svc, $target, $config->{$type}->{$key}->{'services'}->{$svc});
						} else {
							print "WARNING: Unknown type $type -- please fix this...\n";
						}
					}
				}

				if ($type eq 'targets') {
					if (config_is_hash($config->{'targets'}->{$key}->{'tunnels'})) {
						foreach $tun (keys %{$config->{'targets'}->{$key}->{'tunnels'}}) {
							debug("Process target $target tunnel: $tun");
							process_target_tunnel($tun, $target, $config->{'targets'}->{$key}->{'tunnels'}->{$tun});
						}
					}
				}
			} while (++$ips);
		}
	}
}

=item I<process_target_tunnel("tunnel name", "target name", $config_hash_ref)>

Adds rules to accept tunnel traffic, this is mostly for supporting LVS
services where traffic gets changed at the firewall.

=cut

sub process_target_tunnel {
	my ($name, $target, $tunnel) = @_;
	return unless config_is_hash($tunnel);
	use vars qw(@temp $rule);


	if ($tunnel->{'mode'} eq 'nat') {
		outline("# target $target LVS/NAT tunnel $name");
		if (!config_is_hash($tunnel->{'ports'})) {
			print "WARNING: No ports defined for LVS NAT tunnel: $target -- this is dangerous!\n";
			iptables("-A OUTPUT -o " . $config->{'inside'} . " -s " . $config->{'anywhere'} . " -d $target -j ACCEPT");
			return;
		}

		verify_ports($tunnel);
		foreach (keys %{$tunnel->{'ports'}}) {
			if (($tunnel->{'ports'}->{$_} eq 'tcp') or ($tunnel->{'ports'}->{$_} eq 'both')) {
				iptables("-A OUTPUT -o " . $config->{'inside'} . " -s " . $config->{'anywhere'} . " -d $target -p tcp --dport $_ -j ACCEPT");
			}
			if (($tunnel->{'ports'}->{$_} eq 'udp') or ($tunnel->{'ports'}->{$_} eq 'both')) {
				iptables("-A OUTPUT -o " . $config->{'inside'} . " -s " . $config->{'anywhere'} . " -d $target -p udp --dport $_ -j ACCEPT");
			}
		}
	}

	if ($tunnel->{'mode'} eq 'ipip') {
		outline("# target $target LVS/TUN tunnel $name");
		if (!config_is_array($tunnel->{'sources'})) {
			@temp = ($config->{'anywhere'});
			$tunnel->{'sources'} = \@temp;
		}
		foreach (@{$tunnel->{'sources'}}) {
			iptables("-p 4 -s $_ -d $target -j ACCEPT", "", qw(OUTPUT FORWARD));
		}
	}

	outline();
}

sub process_local_service {
	my ($name,$target,$service) = @_;

	$service->{'target'} = $target;
	$service->{'forward'} = 0;

	process_service($name, $service);
}

sub process_target_service {
	my ($name,$target,$service) = @_;
	
	$service->{'target'} = $target;
	$service->{'forward'} = 1;

	process_service($name, $service);
}

sub process_service {
	my ($name,$service) = @_;

	verify_interfaces($service);
	check_ports($name, $service);
	verify_order($service);
	process_allowdeny($service);
	generate_rules($name, $service);
}

sub verify_interfaces {
	my ($service) = @_;

	$service->{'inside'} = $config->{'inside'} unless $service->{'inside'};
	$service->{'outside'} = $config->{'outside'} unless $service->{'outside'};
}

sub check_ports {
	my ($name, $service) = @_;

	if (!config_is_hash($service->{'ports'})) {
		find_ports($name, $service);
	} else {
		verify_ports($service);
	}
}

sub verify_ports {
	my ($service) = @_;
	use vars qw($port $proto);
	debug("Checking ports");
	foreach $port (keys %{$service->{'ports'}}) {
		my @p;
		if ($port =~ /^([0-9]+):([0-9]+)$/) {
			for (my $x = $1; $x <= $2; $x++) {
				push @p, $x;
			}
		} else {
			push @p, $port;
		}
		$proto = $service->{'ports'}->{$port};
		die "ERROR: protocl must be tcp, udp or both ($proto specified)" if (($proto ne 'both') and ($proto ne 'tcp') and ($proto ne 'udp'));
		foreach (@p) {
			die "ERROR: port must be between 1 and 65535 ($_ specified)" if (($_ < 0) or ($_ > 65535));
		}
		debug(" - $port $proto");
	}
}

sub find_ports {
	local $_;
	my ($name, $service) = @_;
	use vars qw($svcount $sname $portspec $port $proto);

	debug("Finding ports for $name");

	# first handle some special cases
	if (lc($name) eq 'ssh') {
		$service->{'ports'}->{'22'} = 'tcp';
	
	# now use /etc/services
	} else {
		$svcount = 0;
		open(SVCS, "$grep ^$name /etc/services |") or die("Couldn't spawn $grep: $!");
		while (<SVCS>) {
			chomp;
			s/[ \s\t]+/ /g;
			($sname, $portspec, undef) = split;
			next unless ($sname eq $name);
			($port, $proto) = split(/\//, $portspec);
			if (($service->{'ports'}->{$port}) and ($service->{'ports'}->{$port} ne $proto) and (($proto eq 'tcp') or ($proto eq 'udp'))) {
				$service->{'ports'}->{$port} = 'both';
			} else {
				$service->{'ports'}->{$port} = $proto;
			}
			$svcount++;
		}
		close(SVCS);

		die "ERROR: Could not find port specification for $name in /etc/services. Add port definition to service." unless ($svcount > 0);
	}

	if ($debug == 1) {
		foreach my $key (keys %{$service->{'ports'}}) {
			debug(" - $key " . $service->{'ports'}->{$key});
		}
	}
}

sub verify_order {
	my ($service) = @_;
	use vars qw($first $second);

	debug("Verifying order");

	if ($service->{'order'}) {
		if (!config_is_array($service->{'order'})) {
			die "ERROR: order must be an array";
		}

		$first = $service->{'order'}->[0];
		$second = $service->{'order'}->[1];
		if (($first eq "allow") and ($second ne "deny")) {
			die "ERROR: allow must be followed by deny";
		} elsif (($first eq "deny") and ($second ne "allow")) {
			die "ERROR: deny must be followed by allow";
		} elsif (($first ne "allow") and ($first ne "deny")) {
			die "ERROR: unknown order value: $first, $second";
		}
	} else {
		$service->{'order'}->[0] = 'allow';
		$service->{'order'}->[1] = 'deny';
	}

	debug(" - " . $service->{'order'}->[0] . " then " . $service->{'order'}->[1]);
}

sub process_allowdeny {
	my ($service) = @_;
	my ($tempref, $i, $key);

	debug("Processing allow & deny");

	# compute allow & deny
	foreach (qw(allow deny)) {
		undef $tempref;

		if (ref($service->{$_}) eq 'HASH') {
			foreach $key (keys %{$service->{$_}}) {
				undef $tempref;
				if (($key eq 'inbound') or ($key eq 'outbound') or ($key eq 'source') or ($key eq 'destination')) {
					if (ref($service->{$_}->{$key}) eq 'ARRAY') {
						$i = 0;
						foreach (@{$service->{$_}->{$key}}) {
							$tempref->[$i] = $_;
							$i++;
						}
					} else {
						$tempref->[0] = $service->{$_}->{$key};
					}
				} else {
					print "WARNING: unknown member of $_: $key\n";
				}
				$service->{$_}->{$key} = $tempref;
			}
		} elsif (ref($service->{$_}) eq 'ARRAY') {
			$i = 0;
			foreach (@{$service->{$_}}) {
				$tempref->{'inbound'}->[$i] = $tempref->{'outbound'}->[$i] = $_;
				$i++;
			}
			$service->{$_} = $tempref;
		} elsif ($service->{$_}) {
			$tempref->{'inbound'}->[0] = $tempref->{'outbound'}->[0] = $service->{$_};
			$service->{$_} = $tempref;
		} else {
			$tempref->{'inbound'}->[0] = $tempref->{'outbound'}->[0] = "none" if ($_ eq 'allow');
			$tempref->{'inbound'}->[0] = $tempref->{'outbound'}->[0] = "all" if ($_ eq 'deny');
			$service->{$_} = $tempref;
		}
	}
	foreach (qw(allow deny)) {
		foreach $key (qw(inbound outbound)) {
			if (!$service->{$_}->{$key}) {
				undef $tempref;
				$tempref->[0] = "none";
				$service->{$_}->{$key} = $tempref;
			}
		}
		foreach $key (qw(source destination)) {
			if (!$service->{$_}->{$key}) {
				undef $tempref;
				$tempref->[0] = "all";
				$service->{$_}->{$key} = $tempref;
			}
		}
	}
}

sub generate_rules {
	my ($name, $service) = @_;
	use vars qw($port $order %dispatch);

	debug("Generating rules: $name");
	$service->{'name'} = $name;

	$service->{'type'} = 'both' unless (($service->{'type'}) and (($service->{'type'} eq 'client') or ($service->{'type'} eq 'server')));
	
	# maps ports & names to specific functions to handle certain protocols
	%dispatch = (
		'21' => \&ftp_rule,
		'ftp' => \&ftp_rule,

		'22' => \&ssh_rule,
		'ssh' => \&ssh_rule,

		'53' => \&dns_rule,
		'dns' => \&dns_rule,

		'123' => \&ntp_rule,
		'ntp' => \&ntp_rule,
	);

	foreach $port (keys %{$service->{'ports'}}) {
		if (exists $dispatch{$port}) {
			$dispatch{$port}->($port, 'tcp', $service) if (($service->{'ports'}->{$port} eq 'tcp') or ($service->{'ports'}->{$port} eq 'both'));
			$dispatch{$port}->($port, 'udp', $service) if (($service->{'ports'}->{$port} eq 'udp') or ($service->{'ports'}->{$port} eq 'both'));
		} elsif (exists $dispatch{$name}) {
			$dispatch{$name}->($port, 'tcp', $service) if (($service->{'ports'}->{$port} eq 'tcp') or ($service->{'ports'}->{$port} eq 'both'));
			$dispatch{$name}->($port, 'udp', $service) if (($service->{'ports'}->{$port} eq 'udp') or ($service->{'ports'}->{$port} eq 'both'));
		} else {
			generic_rule($port, 'tcp', $service) if (($service->{'ports'}->{$port} eq 'tcp') or ($service->{'ports'}->{$port} eq 'both'));
			generic_rule($port, 'udp', $service) if (($service->{'ports'}->{$port} eq 'udp') or ($service->{'ports'}->{$port} eq 'both'));
		}
	}
}

sub compiler {
	my ($type, $policy, $destinations, $sources, $int1, $int2, $chain1, $chain2, $proto, $sport, $dport, $service, $states, $rules) = @_;
	use vars qw($i $rule_1 @rules_1 $rule_2 @rules_2 $out $src $dst $need_second $source $destination $ifmatch1 $ifmatch2 @temp);

	@rules_1 = ();
	@rules_2 = ();
	$need_second = 1;

	DESTINATION: foreach $destination (@{$service->{$policy}->{$destinations}}) {
		if ($destination eq 'none') {
			debug(" - access disabled (destination = none)");
			@{$rules} = ();
			$need_second = 0;
			last;
		} 

		if ($service->{'forward'} == 1) {
			$rule_1 = "-A FORWARD";
			$rule_2 = "-A FORWARD";
			if ($int1 ne 'none') {
				if ($config->{'mode'} eq 'bridge') {
					$rule_1 .= " -m physdev --physdev-in ";
					$rule_2 .= " -m physdev --physdev-out ";
				} else {
					$rule_1 .= " -i ";
					$rule_2 .= " -o ";
				}
				$rule_1 .= $int1;
				$rule_2 .= $int1;
			}
			if ($int2 ne 'none') {
				if ($config->{'mode'} eq 'bridge') {
					$rule_2 .= " -m physdev --physdev-in ";
					$rule_1 .= " -m physdev --physdev-out ";
				} else {
					$rule_2 .= " -i ";
					$rule_1 .= " -o ";
				}
				$rule_2 .= $int2;
				$rule_1 .= $int2;
			}
		} else {
			if ($config->{'mode'} eq 'bridge') {
				$int1 = $config->{'bridge'} unless ($int1 eq 'none');
				$int2 = $config->{'bridge'} unless ($int2 eq 'none');
			}
      
			$ifmatch1 = ($chain1 =~ /input/i ? 'i' : 'o') if ($int1 ne 'none');
			$ifmatch2 = ($ifmatch1 eq 'i' ? 'o' : 'i') if ($int2 ne 'none');
			$rule_1 = "-A $chain1" . ($int1 ne 'none' ? " -$ifmatch1 $int1" : "");
			$rule_2 = "-A $chain2" . ($int2 ne 'none' ? " -$ifmatch2 $int2" : "");
		}
		$rule_1 .= " -p $proto --sport $sport --dport $dport";
		$rule_2 .= " -p $proto --sport $dport --dport $sport";

		if (config_is_array($states) != 1) {
			undef $states;
			if ($service->{'states'}) {
				if ((ref($service->{'states'}) eq 'ARRAY') and (@{$service->{'states'}} == 2)) {
					$states = $service->{'states'};
				} elsif ($service->{'states'} eq 'no') {
					@temp = ();
					$states = \@temp;
				}
			}
		}
		if (($states) and (@{$states} > 0) and (@{$states} != 2)) {
			print "WARNING: " . $service->{'name'} . ": states can be an array with exactly two items or the word no. Defaulting to NEW,ESTABLISHED ESTABLISHED,RELATED\n";
			undef $states;
		}
		if (!$states) {
			@temp = ('NEW,ESTABLISHED', 'ESTABLISHED,RELATED');
			$states = \@temp;
		}
		if (@{$states} == 2) {
			$rule_1 .= " -m state --state " . $states->[0];
			$rule_2 .= " -m state --state " . $states->[1];
		}

		if ($destination eq 'all') {
			if ($type eq 'server') {
				$dst = $service->{'target'};
			} else {
				$dst = $config->{'anywhere'};
			}
		} elsif ($config->{'interfaces'}->{$destination}) {
			$dst = $config->{'interfaces'}->{$destination}->{'addr'};
		} else {
			$dst = $destination;
		}

		foreach $source (@{$service->{$policy}->{$sources}}) {
			if ($source eq 'all') {
				if ($type eq 'client') {
					$src = $service->{'target'};
				} else {
					$src = $config->{'anywhere'};
				}

				if ($destination eq 'all') {
					debug(" - $policy: all access (destination = all / source = all)");
					@${rules} = ($rule_1 . " -s $src -d $dst -j ACCEPT", $rule_2 . " -s $dst -d $src -j ACCEPT");
					$need_second = 0;
					last DESTINATION;
				}
			} elsif ($config->{'interfaces'}->{$source}) {
				$src = $config->{'interfaces'}->{$source}->{'addr'};
			} else {
				$src = $source;
			}
			push @rules_1, $rule_1 . " -s $src -d $dst -j " . ($policy eq 'allow' ? 'ACCEPT' : ($service->{'forward'} ? 'FORWARDLOGDROP' : $chain1 . "LOGDROP"));
			push @rules_2, $rule_2 . " -s $dst -d $src -j " . ($policy eq 'allow' ? 'ACCEPT' : ($service->{'forward'} ? 'FORWARDLOGDROP' : $chain2 . "LOGDROP"));
		}

		for ($i = 0; $i < @rules_1; $i++ ) {
			push @{$rules}, $rules_1[$i];
			push @{$rules}, $rules_2[$i];
		}

		@rules_1 = ();
		@rules_2 = ();
	}


	return $need_second;
}

sub compile_client_rule {
	my ($sport, $dport, $proto, $service, @states) = @_;
	return unless (($service->{'type'} eq 'client') or ($service->{'type'} eq 'both'));
	use vars qw($i @rules $need_second $log $int1 $int2);

	$log = ($service->{'forward'} == 1 ? "target" : "local") . " client rule - " . $service->{'target'} . ": " . $service->{'name'} . " ($sport, $dport, $proto)";
	debug("Compiling $log");
	outline("# $log");

	$int1 = (($service->{'forward'} == 1) ? $service->{'inside'} : $service->{'outside'});
	$int2 = (($service->{'forward'} == 1) ? $service->{'outside'} : $service->{'outside'});

	$need_second = 1;
	foreach ($i = 0; $i < 2; $i++) {
		@rules = ();
		$need_second = compiler('client', $service->{'order'}->[$i], 'outbound', 'source', $int1, $int2, 'OUTPUT', 'INPUT', $proto, $sport, $dport, $service, \@states, \@rules);
		foreach (@rules) {
			iptables($_);
		}

		last unless ($need_second == 1);
	}

	outline();
}

sub compile_server_rule {
	my ($sport, $dport, $proto, $service, @states) = @_;
	return unless (($service->{'type'} eq 'server') or ($service->{'type'} eq 'both'));
	use vars qw($i @rules $need_second $int1 $int2);

	$log = ($service->{'forward'} == 1 ? "target" : "local") . " server rule - " . $service->{'target'} . ": " . $service->{'name'} . " ($sport, $dport, $proto)";
	debug("Compiling $log");
	outline("# $log");

	$int1 = (($service->{'forward'} == 1) ? $service->{'outside'} : $service->{'outside'});
	$int2 = (($service->{'forward'} == 1) ? $service->{'inside'} : $service->{'outside'});

	$need_second = 1;
	foreach ($i = 0; $i < 2; $i++) {
		@rules = ();
		$need_second = compiler('server', $service->{'order'}->[$i], 'destination', 'inbound', $int1, $int2, 'INPUT', 'OUTPUT', $proto, $sport, $dport, $service, \@states, \@rules);
		foreach (@rules) {
			iptables($_);
		}

		last unless ($need_second == 1);
	}

	outline();
}

sub compile_rules {
	my ($sport, $dport, $proto, $service, @states) = @_;
	compile_client_rule($sport, $dport, $proto, $service, @states);
	compile_server_rule($sport, $dport, $proto, $service, @states);
}

sub ssh_rule {
	my ($port, $proto, $service) = @_;
	return unless ($proto eq 'tcp');

	debug("SSH Rule");

	foreach (qw(unprivports ssh_unprivports)) {
		compile_rules($config->{$_}, $port, 'tcp', $service);
	}
}

sub ntp_rule {
	my ($port, $proto, $service) = @_;
	return unless ($proto eq 'udp');

	debug("NTP Rule");

	compile_rules($config->{'unprivports'}, $port, $proto, $service);
	compile_rules($port, $port, $proto, $service);
}

sub dns_rule {
	my ($port, $proto, $service) = @_;

	debug("DNS Rule");

	if ($proto eq 'udp') {
		compile_rules($config->{'unprivports'}, $port, $proto, $service);
		compile_server_rule($port, $port, $proto, $service);
	} else {
		compile_server_rule($config->{'unprivports'}, $port, $proto, $service);
	}
}

sub ftp_rule {
	my ($port, $proto, $service) = @_;
	return unless ($proto eq 'tcp');

	debug ("FTP Rule");

	compile_rules($config->{'unprivports'}, $port, $proto, $service, ('NEW,ESTABLISHED', 'ESTABLISHED,RELATED'));
	compile_rules(($port - 1), $config->{'unprivports'}, $proto, $service, ('ESTABLISHED,RELATED', 'ESTABLISHED'));
	compile_rules($config->{'unprivports'}, $config->{'unprivports'}, $proto, $service, ('ESTABLISHED', 'ESTABLISHED,RELATED'));
}

sub generic_rule {
	my ($port, $proto, $service) = @_;

	debug("Generic Rule");

	compile_rules($config->{'unprivports'}, $port, $proto, $service);
}

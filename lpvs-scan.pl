#!/usr/bin/perl -w

# Copyright (c) 2012-2014  Lars Windolf <lars.windolf@gmx.de>
# Copyright (C) 2004-2010 John Peacock <jpeacock@cpan.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

use 5.010;
use strict;
use Term::ANSIColor;
use XML::LibXSLT;
use XML::LibXML;
use LWP::UserAgent;
use Getopt::Std;

################################################################################
# OS Configuration
################################################################################

my $apt_show_versions = 'apt-show-versions |grep "security upgradeable"';
my $aptitude = 'aptitude search "?and(~U,~Asecurity)"';

my %config = (
	'os' => {
		'Ubuntu' => {
			'pkgtype'	=> 'deb',
			'pkgsource'	=> 'description',
			'feed'		=> 'http://www.ubuntu.com/usn/rss.xml',
			'upgrades'	=> [('/usr/lib/update-notifier/apt-check -p', $apt_show_versions, $aptitude)],
			'revsplit'	=> '(-|~|ubuntu)'
		},
		#'Debian' => {
		#	'pkgtype'	=> 'deb',
		#	'pkgsource'	=> 'link',
		#	'feed'		=> 'http://www.debian.org/security/dsa-long',
		#	'upgrades'	=> [('debsecan --format packages', $apt_show_versions, $aptitude)],
		#	'revsplit'	=> '(-|~)'
		#},
		#'Redhat' => {
		#	'pkgtype'	=> 'rpm',
		#	'pkgsource'	=> 'link',
		#	'feed'		=> 'https://rhn.redhat.com/rpc/recent-errata.pxt'
		#},
		'CentOS' => {
			'pkglist'	=> 'rpm -qa',
			'pkgtype'	=> 'rpm',
			'pkgquery'	=> 'rpm -q',
			'pkgsource'	=> 'description',
			'feed'		=> 'https://admin.fedoraproject.org/updates/rss/rss2.0?type=security'
			# FIXME: define revsplit
		}
	},
	'pkg' => {
		'deb' => {
			'list'			=> 'dpkg -l | grep "^ii"',
			'query'			=> 'dpkg -p',
			'querytoversion'	=> 'Version:\s+(\S+)'
		},
		'rpm' => {
			'list'			=> 'rpm -qa',
			'query'			=> 'rpm -q --queryformat="%{VERSION}-%{RELEASE}.%{ARCH}" ',
			'querytoversion'	=> '^(.*)$'
		}
	}
);

my $verbose = 0;
my $silent = 0;
my $debug = 0;
my %opts;

getopts('hsvduV', \%opts);

if($opts{'h'}) {
	print "\nUsage: $0 -hsvduV\n\n";
	print "	-h	Print this help text.\n";
	print "	-s	Silent mode. Only print warnings and errors.\n";
	print " -v	Verbose mode. Explains about skipped vulnerabilites.\n";
	print " -d	Debug mode. Explains about version comparisons.\n";
	print "	-u	Check for security upgrades with OS specific check.\n";
	print "	-V	Disable feed based checking.\n";
	print "\n";
	exit(0);
}

$silent = 1 if($opts{'s'});
$verbose = 1 if($opts{'v'});
$debug = 1 if($opts{'d'});

# Check for color support
unless(-t 1 and `tput colors` >= 8) {
	$ENV{'ANSI_COLORS_DISABLED'} = 1;
}

################################################################################
# Startup Checks
################################################################################

# First try lsb_release (we expect this to exist on Ubuntu, but have a fallback for CentOS)
my $os = `lsb_release -is 2>/dev/null`;
chomp $os;

# CentOS fallback 
if(-f "/etc/redhat-release") {
	# /etc/redhat-release should have something like "CentOS release 5.x (xxx)
	my $tmp = `cat /etc/redhat-release`;
	if($tmp =~ /^CentOS\s+release\s+/) {
		$os = "CentOS";
	} else {
		print STDERR "This Redhat-based distribution is not supported! Consider hacking $0 to add support.\n";
		exit(1);
	}
}

if($os eq "") {
	print STDERR "Could not determine OS. Ensure 'lsb_release -s -i' works!\n";
	exit(1);
}

unless(defined($config{'os'}->{$os})) {
	print STDERR "Sorry '$os' is currently not supported! Consider hacking $0 to add support.\n";
	exit(1);
}

# Select configuration
my $osConfig = $config{'os'}->{$os};
my $pkgConfig = $config{'pkg'}->{$osConfig->{'pkgtype'}};

my $packageList = `$pkgConfig->{'list'}`;
print scalar $packageList =~ tr/\n// unless($silent);
print " $os packages are installed.\n" unless($silent);

################################################################################
# Compare two versions 
#
# $1	a safe version
# $2	the version to check if it is safe
#
# Returns
#	-1	if first version is older
#	0	for identical or package with higher revision
#	1	if first version is newer
################################################################################
sub compare_versions {
	my ($version1, $version2) = @_;
	my $result = 0;

	# Split everything
	print "Compare $version1 <=> $version2... " if($debug);
	if($version1 ne $version2) {

	if($osConfig->{'pkgtype'} eq 'deb') {
		`dpkg --compare-versions "$version1" eq "$version2"`;
		if($? != 0) {
			`dpkg --compare-versions "$version1" lt "$version2"`;
			if($? == 0) {
				$result = -1;

				# We need to analyze revisions before deciding
				# this case to distinguish cases like those:
				#
				# 	1.2.0-3ubuntu1.3 < 1.2.0-3.ubuntu1.2 (MATCH)
				# and
				#	1.2.0-3ubuntu1.3 < 1.5.0-4.ubuntu1.0 (MISS)
				#
				# So we compare versions and revisions
				if(defined($osConfig->{'revsplit'})) {
					my @tmp1 = split /$osConfig->{'revsplit'}/, $version1;
					my @tmp2 = split /$osConfig->{'revsplit'}/, $version2;
					$result = 0 if($tmp1[0] eq $tmp2[0]);
					print "    revision detail: version #1: $tmp1[0] version #2: $tmp2[0] => " if($debug);
				}
			} else {
				$result = 1;
			}
		} elsif($osConfig->{'pkgtype'} eq 'rpm') {
			my $dir = dirname($0);
			`$dir/rpm_vercmp.py "$version1" "$version2"`;
			$result = $?;
		} else {
			die "No version comparison for this pkgtype yet.";
		}
	}
	}

	print $result . "\n" if($debug);
	return $result;
}

unless(defined($opts{'V'})) {

################################################################################
# Fetch Advisory Feed
################################################################################

print "Downloading advisory feed '$osConfig->{feed}' ...\n" unless($silent);

my $ua = LWP::UserAgent->new;
$ua->timeout(10);
$ua->env_proxy;
 
my $response = $ua->get($osConfig->{'feed'});
unless ($response->is_success) {
	die "Failed to fetch advisory feed! (".$response->status_line.")";
}

# XSLT for Feed Normalization
my $feed_xslt = <<EOT
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
  xmlns:rss="http://purl.org/rss/1.0/"
  exclude-result-prefixes="rss">

<!-- match RSS feeds -->
<xsl:template match="/rss/channel">
	<feed>
	<xsl:for-each select="item">
		<xsl:copy>
			<title><xsl:apply-templates select="title"/></title>
			<link><xsl:apply-templates select="link"/></link>
			<description><xsl:apply-templates select="description"/></description>
		</xsl:copy>
	</xsl:for-each>
	</feed>
</xsl:template>

<xsl:template match="/rdf:RDF">
	<feed>
	<xsl:for-each select="rss:item">
		<xsl:copy>
			<title><xsl:apply-templates select="rss:title"/></title>
			<link><xsl:apply-templates select="rss:link"/></link>
			<description><xsl:apply-templates select="rss:description"/></description>
		</xsl:copy>
	</xsl:for-each>
	</feed>
</xsl:template>

<!-- match Atom feeds -->
<!-- FIXME -->

</xsl:stylesheet>
EOT
;

# Normalize Feed
my $parser = XML::LibXML->new();
my $xslt = XML::LibXSLT->new();
my $source = $parser->parse_string($response->decoded_content);
my $style_doc = $parser->parse_string($feed_xslt);
my $stylesheet = $xslt->parse_stylesheet($style_doc);
my $results = $stylesheet->transform($source);
my $tmp = $stylesheet->output_string($results);
my $doc = $parser->parse_string($stylesheet->output_string($results));

################################################################################
# Process Advisories
################################################################################

foreach my $item ($doc->documentElement()->getChildrenByTagName("item")) {
	my $title = @{$item->getChildrenByTagName("title")}[0]->textContent;
	my $description = @{$item->getChildrenByTagName("description")}[0]->textContent;
	chomp $title;

	my $found = 0;
	my $vulnerable = 0;
	my %packages;

        # Skip vulnerability if acknowledged
        if($title =~ /^\s*([a-zA-Z0-9\-_\.]+):/) {
                if(-f "$ENV{HOME}/.lpvs/$1") {
                        print color 'bold yellow';
                        print "$title (acknowledged)\n";
                        print color 'reset';
                        next;
                }
        }

	# Determine packages affected by advisory
	#
	# a) from with description text
	if($osConfig->{'pkgsource'} eq 'description') {
		if($osConfig->{'pkgtype'} eq 'deb') {
			# Ubuntu variant
			my @tmp = ($description =~ m#href=.https://launchpad.net/ubuntu/\+source/[^>]*>([^<]+)</a>#g);
			do {
				my $package = shift(@tmp);
				my $version = shift(@tmp);
				${$packages{$package}} = {} unless(defined(${$packages{$package}}));
				${$packages{$package}}->{$version} = 1;
			} while(@tmp);
		}

		# in text RPM variant
		if($osConfig->{'pkgtype'} eq 'rpm') {
			my @tmp = ($description =~ m#[\s^](\S+\.rpm)[\s\$]#g);
			foreach my $rpm (@tmp) {
				if($rpm =~ /^(\w+)-([^-]+-[^-]+)\.rpm$/) {
					my ($package, $version) = ($1, $2);					
					${$packages{$package}} = {} unless(defined(${$packages{$package}}));
					${$packages{$package}}->{$version} = 1;
				}
			}
		}

	# b) from title
	#} elsif($osConfig->{'pkgsource'} eq 'title') {
	}

	foreach my $package (keys %packages) {
		my $installed = 0;
		my $installedVersion;

		# Generic install check
		if($packageList =~ /$package/) {
			if(`$pkgConfig->{query} $package 2>/dev/null` =~ /$pkgConfig->{'querytoversion'}/) {
				# FIXME: RPM might return multiple installed package versions!
				$installedVersion = $1;
				$installed = 1;
			}
		}

		# Check for vulnerable version
		if($installed) {
			$found = 1;

			foreach my $version (keys %{${$packages{$package}}}) {
				my $result = compare_versions($version, $installedVersion);
				if($verbose) {
					print color 'bold green' if($result == 0);
					print color 'bold yellow' if($result == 1);
					print color 'bold green' if($result == -1);
					print color 'reset';
				}

				# Simple case: one of the versions fixing the issue
				# is currently installed. We need no further checking
				if($result == 0) {
					$vulnerable = 0;
					last;
				}

				# The current version is older than at least one of
				# the suggested versions (old distro)
				$vulnerable = 1 if($result > 0);
			}
			if($vulnerable == 1) {
				print color 'bold red';
				print "$title\n";
				print "   -> Vulnerable '$package' version $installedVersion installed!\n\n";
				print color 'reset';
				print "      You should update to one the following versions:\n\n";
				foreach my $version (keys %{${$packages{$package}}}) {
					print "         $version\n";
				}
				print "\n";
			}

		}
	}

	# When we find no packages 
	unless($silent) {
		unless($found) {
			if($verbose) {
				print color 'yellow';
				print "$title\n";
			}
		} else {
			unless($vulnerable) {
				print color 'bold green';
				print "$title\n";
			}
		}
		print color 'reset';
	}
}
}

# Check for other uninstalled security upgrades (not listed by security feed)
if($opts{'u'}) {
	if(defined($osConfig->{'upgrades'})) {
		foreach(@{$osConfig->{'upgrades'}}) {
			my $output = `$_ 2>&1`;
			if($? eq 0) {	
				print color 'bold yellow';
				# FIXME: Useful warning output
				print "WARNING: '$_' reports additional available security upgrades:\n";
				print $output . "\n";
				print color 'reset';
				last;
			}
		}
	} else {
		print "WARNING: Sorry, no upgrade check supported for this distro!\n";
	}
}

print "Done.\n" unless($silent);

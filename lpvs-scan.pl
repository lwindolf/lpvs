#!/usr/bin/perl -w

# Copyright (c) 2012-2013  Lars Windolf <lars.lindner@gmail.com>
# Copyright (C) 2004-2010 John Peacock <jpeacock@cpan.org>
#
# The versioncmp() method is from the CPAN Version.pm from John Peacock.
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

use strict;
use Term::ANSIColor;
use XML::LibXSLT;
use XML::LibXML;
use LWP::UserAgent;
use Getopt::Std;

################################################################################
# OS Configuration
################################################################################

my %config = (
	'os' => {
		'Ubuntu' => {
			'pkgtype'	=> 'deb',
			'pkgsource'	=> 'description',
			'feed'		=> 'http://www.ubuntu.com/usn/rss.xml'
		},
		#'Debian' => {
		#	'pkgtype'	=> 'deb',
		#	'pkgsource'	=> 'link',
		#	'feed'		=> 'http://www.debian.org/security/dsa-long'
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
		}
	},
	'pkg' => {
		'deb' => {
			'list'			=> 'dpkg -l',
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

getopts('svo:', \%opts);

$silent = 1 if($opts{'s'});
$verbose = 1 if($opts{'v'});

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
# Fetch Advisory Feed
################################################################################

# Download Feed
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

################################################################################
# Debian (not Ubuntu) and RPM version splitter
################################################################################
sub split_standard_version {
	my ($version) = @_;
	my %v;

	if($version =~ /-/) {
		$version =~ /^((?<epoch>\d+):)?(?<upstream>.+)-(?<revision>[^-]+)/;
		if($debug) {
			print "split w/ '-': ";
			print " epoch=$+{epoch}" if($+{'epoch'});
			print " up=$+{upstream} rev=$+{revision} ($version)\n";
		}
		%v = %+;
	} else {
		$version =~ /^((?<epoch>\d+):)?(?<upstream>.+)/;
		if($debug) {
			print "split w/o '-': ";
			print " epoch=$+{epoch}" if($+{'epoch'});
			print " up=$+{upstream} rev=$+{revision} ($version)\n";
		}
		%v = %+;
	}

	$v{'epoch'} = "" unless(defined($v{'epoch'}));
	$v{'revision'} = "" unless(defined($v{'revision'}));

	# Removed suffixes: e.g. "15.0.1+build1-0ubuntu0.12.04.1" will lead
	# to $v{'version'} set to "15.0.1+build1" which will fail to compare
	# correctly to say "15.0+build1", so we strip useless "+" suffixes
	$v{'upstream'} =~ s/\+.+//;

	return %v;
}

################################################################################
# Ubuntu splitter: like Debian, but has a second revision separated by "ubuntu"
#
# Example: "2.6.12-1ubuntu1" -> version "2.6.12" revision "1" revision2 "1"
################################################################################
sub split_ubuntu_version {
	my ($version) = @_;
	my $ubuntu_revision;
	my %v;

	if($version =~ s/ubuntu([\d.]+)$//g) {
		$ubuntu_revision = $1;
	}

	%v = split_standard_version($version);

	if(defined($ubuntu_revision)) {
		print "   ubuntu revision=$ubuntu_revision\n" if($debug);
		$v{'revision2'} = $ubuntu_revision;
	}

	return %v;
}

################################################################################
# Generic splitter method
#
# $1	version string to split
#
# return hash with version parts
################################################################################
sub split_version {

	return split_ubuntu_version($_[0]) if($os eq "Ubuntu");
	return split_standard_version($_[0]);
}

################################################################################
# This method is from Ed Avis Sort-Versions-1.5 
# (http://search.cpan.org/~edavis/Sort-Versions-1.5/Versions.pm)
#
# Copyright (c) 1996, Kenneth J. Albanowski. All rights reserved.  This
# program is free software; you can redistribute it and/or modify it under
# the same terms as Perl itself.
################################################################################
sub versioncmp( $$ ) {
    return 0 unless(defined($_[0])); 
    return 0 unless(defined($_[1]));

    my @A = ($_[0] =~ /([-.]|\d+|[^-.\d]+)/g);
    my @B = ($_[1] =~ /([-.]|\d+|[^-.\d]+)/g);

    my ($A, $B);
    while (@A and @B) {
	$A = shift @A;
	$B = shift @B;

	if ($A eq '-' and $B eq '-') {
	    next;
	} elsif ( $A eq '-' ) {
	    return -1;
	} elsif ( $B eq '-') {
	    return 1;
	} elsif ($A eq '.' and $B eq '.') {
	    next;
	} elsif ( $A eq '.' ) {
	    return -1;
	} elsif ( $B eq '.' ) {
	    return 1;
	} elsif ($A =~ /^\d+$/ and $B =~ /^\d+$/) {
	    if ($A =~ /^0/ || $B =~ /^0/) {
		return $A cmp $B if $A cmp $B;
	    } else {
		return $A <=> $B if $A <=> $B;
	    }
	} else {
	    $A = uc $A;
	    $B = uc $B;
	    return $A cmp $B if $A cmp $B;
	}	
    }

    @A <=> @B;
}

################################################################################
# Split a version in Debian format and compare it's parts. As it works fine for
# RPM too we do not use a separate comparison for now.
################################################################################
sub compare_versions {
	my ($version1, $version2) = @_;

	# FIXME implement Debian ~ sorting exception (~ sorts earlier than everything
	# FIXME implement Debian number sorting expection (numbers sort earlier than letters)

	# Handle according to Debian format [epoch:]upstream_version[-debian_revision] 

	# Split everything
	print "Compare $version1 <=> $version2...\n" if($debug);
	my %v1 = split_version($version1);
	my %v2 = split_version($version2);
	my $result;

	$result = ($v1{'epoch'} cmp $v2{'epoch'});
	if($result != 0) {
		print "   => epoch differs: ($v1{epoch} <=> $v2{epoch}) = $result\n" if($debug);
		return $result;
	}

	$result = versioncmp($v1{'upstream'}, $v2{'upstream'});
	if($result != 0) {
		print "   => upstream differs: ($v1{upstream} <=> $v2{upstream}) = $result\n" if($debug);
		return $result;
	}

	$result = versioncmp($v1{'revision'}, $v2{'revision'});
	if($result != 0) {
		print "   => revision differs: ($v1{revision} <=> $v2{revision}) = $result\n" if($debug);
		return $result;
	}

	if(defined($v1{'revision2'})) {
		$result = versioncmp($v1{'revision2'}, $v2{'revision2'});
		if($result != 0) {
			print "   => revision2 differs: ($v1{revision2} <=> $v2{revision2}) = $result\n" if($debug);
			return $result;
		}
	}

	return 0;
}

################################################################################
# Main
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
				print "      You should update to the following version:\n\n";
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

print "Done.\n" unless($silent);

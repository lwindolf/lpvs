#!/usr/bin/perl -w

sub versioncmp( $$ ) {
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

sub test($$) {
	my ($v1, $v2) = @_;

	print "$v1 <=> $v2 = " . versioncmp($v1, $v2) . "\n";
}

test("1ubuntu1.1", "1ubuntu0");
test("1ubuntu1.1", "1ubuntu1");
test("1ubuntu1.1", "1ubuntu2");
test("1ubuntu1.1", "1ubuntu1.0");
test("1ubuntu1.1", "1ubuntu1.1");
test("1ubuntu1.1", "1ubuntu1.2");
test("1ubuntu2.1", "1ubuntu0");
test("1ubuntu2.1", "1ubuntu1");
test("1ubuntu2.1", "1ubuntu2");


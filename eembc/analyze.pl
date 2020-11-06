#!/usr/bin/env perl
use warnings;
use strict;

# This script reads the output of "contextualize.bash", which are groups of
# functions associated with a context handle, and the handshake state in
# which they were called.
#
# This script then summarizes them by state, base function, and # of bytes,
# providing a total # of bytes in a more compact table. It also alerts of
# contexts have been re-initialized, or cloned.
#
# The output is a slightly  more condensed form of the context file, e.g.:
#
#
# <context id> START
#               ...list of init's and free's (to detect re-init)
# <context id> <state> <mode> <bytes>
# <context id> <state> <mode> <bytes>
# <context id> <state> <mode> <bytes>
# <context id> TOTAL <mode> <bytes>
#
# e.g.,
# 0x55d3058e49c0 START
#                 mbedtls_sha256_init(0x55d3058e49c0)
#                 mbedtls_sha256_free(0x55d3058e49c0)
# 0x55d3058e49c0       14   SHA          192
# 0x55d3058e49c0 TOTAL      SHA          192
#
# In the above example, the context had one init and one free, and utilized
# 192 bytes in state 14.
#
# Or this messy one:
# 0x55d3058e4ad0 START
#                 mbedtls_sha256_init(0x55d3058e4ad0)
#                 mbedtls_sha256_free(0x55d3058e4ad0)
#                 mbedtls_sha256_init(0x55d3058e4ad0)
# 0x55d3058e4ad0       14   SHA          213
#         WARNING: context SHA(0x55d3058e4ad0) is re-initializing
#                 mbedtls_sha256_free(0x55d3058e4ad0)
#                 mbedtls_sha256_init(0x55d3058e4ad0)
# 0x55d3058e4ad0       14   SHA          174
#         WARNING: context SHA(0x55d3058e4ad0) is re-initializing
#                 mbedtls_sha256_free(0x55d3058e4ad0)
#                 mbedtls_sha256_init(0x55d3058e4ad0)
# 0x55d3058e4ad0       14   SHA          174
#         WARNING: context SHA(0x55d3058e4ad0) is re-initializing
#                 mbedtls_sha256_free(0x55d3058e4ad0)
#                 mbedtls_sha256_init(0x55d3058e4ad0)
# 0x55d3058e4ad0       14   SHA          173
#         WARNING: context SHA(0x55d3058e4ad0) is re-initializing
#                 mbedtls_sha256_free(0x55d3058e4ad0)
# 0x55d3058e4ad0       14   SHA          173
# 0x55d3058e4ad0 TOTAL      SHA          907
#
# This context was freed and initd many times in state 14.

#
# There's no guarantee of uniqueness in contexts I think, look at this
#
# pule: mbedtls_sha256_init(0x7ffe88863690)
# pule: mbedtls_sha256_starts(0x7ffe88863690)
# pule: mbedtls_sha256_update:ilen = 32 (0x7ffe88863690)
# pule: mbedtls_sha256_finish(0x7ffe88863690)
# pule: mbedtls_sha256_free(0x7ffe88863690)
# pule: mbedtls_sha256_init(0x7ffe88863690)
# pule: mbedtls_sha256_starts(0x7ffe88863690)
# pule: mbedtls_sha256_update:ilen = 32 (0x7ffe88863690)
# pule: mbedtls_sha256_finish(0x7ffe88863690)
# pule: mbedtls_sha256_free(0x7ffe88863690)
# pule: mbedtls_ecdsa_init(0x7ffe88863690)
# pule: mbedtls_ecdsa_read_signature(0x7ffe88863690):hlen = 32 slen = 71
# pule: mbedtls_ecdsa_free(0x7ffe88863690)
#
# I think we got "lucky" and malloc grabbed the same memory address for
# a hash and an ECDSA. oops. this will be confusing.


my %db;
my $ctx = "NULL";
$db{'totalb'} = 0;
$db{'is-init'} = 0;
$db{'state'} = 0;


while (<>) {
	if (/NEW CONTEXT (\S+)/) {
		if ($ctx ne "NULL") {
			&printAndReset();
			printf "$ctx TOTAL      %-10s %5d\n",  $db{'mode'}, $db{'totalb'};
		}
		$ctx = $1;
		print "\n$ctx START\n";
		# clear state
		undef %db;
		$db{'totalb'} = 0;
		$db{'is-init'} = 0;
		$db{'state'} = 0;

	} elsif (/pule: (.*)/) {
		my $func = $1;
		print "\t\t$func\n" if $func =~ /init/;
#		print "\t\t$func\n";
		if ($func =~ /init/) {
			if ($db{'is-init'}) {
				&printAndReset();
				print "\tWARNING: context $db{'mode'}($ctx) is re-initializing\n";
			}
			$db{'is-init'} = 1;
		}
		if ($func =~ /mbedtls_aes/) {
			$db{'mode'} = "AESECB";
			# init > setkey+ > ecb* > free
			# size = 16
			if ($func =~ /mbedtls_aes_crypt_ecb/) {
				if ($db{'bytes'}) {
					$db{'bytes'} += 16; # always 16
				} else {
					$db{'bytes'} = 16;
				}
				$db{'totalb'} += 16;
			}
		} elsif ($func =~ /mbedtls_gcm/) {
			$db{'mode'} = "GCM";
			if ($func =~ /mbedtls_gcm_update.*length = (\d+)/) {
				if ($db{'bytes'}) {
					$db{'bytes'} += $1
				} else {
					$db{'bytes'} = $1;
				}
				$db{'totalb'} += $1;
			}
		} elsif ($func =~ /mbedtls_sha256/) {
			$db{'mode'} = "SHA";
			if ($func =~ /clone\((0x\S+)/) {
				print "\tWARNING: this context is now a clone of $1\n";
			}
			if ($func =~ /sha256_update.*ilen = (\d+)/) {
				if ($db{'bytes'}) {
					$db{'bytes'} += $1
				} else {
					$db{'bytes'} = $1;
				}
				$db{'totalb'} += $1;
			}
		} elsif ($func =~ /mbedtls_ecdh/) {
			# Not really sure what to do with ECDH functions, just print the
			# function call list and state.
			$db{'mode'} = "ECDH";
			print "\t\tDEBUG: $func [[$db{'state'}]]\n";
		} elsif ($func =~ /mbedtls_ecdsa/) {
			$db{'mode'} = "ECDSA";
			print "\t\tDEBUG: $func [[$db{'state'}]]\n";
			if ($func =~ /mbedtls_ecdsa_read_signature.*slen = (\d+)/) {
				if ($db{'bytes'}) {
					$db{'bytes'} += $1
				} else {
					$db{'bytes'} = $1;
				}
				$db{'totalb'} += $1;
			}
		} elsif ($func =~ /mbedtls_hmac/) {
			$db{'mode'} = "ECDSA";
		} else {
			die "Unknown func $func\n";
		}
		print "\t\t$func\n" if $func =~ /free/;
	} elsif (/client state: (\d+)/) {
		&printAndReset();
		$db{'state'} = $1;
	}
}

sub printAndReset {
	if ($db{'bytes'}) {
		printf "$ctx %8d   %-10s %5d\n", $db{'state'}, $db{'mode'}, $db{'bytes'};
	}
	undef $db{'bytes'};
}

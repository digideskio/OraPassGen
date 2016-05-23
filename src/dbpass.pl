#!/usr/bin/perl -w

use Digest::MD5 qw(md5 md5_hex md5_base64);
use Crypt::OpenSSL::Bignum;
use Getopt::Long;
use MIME::Base64;
use v5.10; # to enable say()
use strict;

sub usage {
my $usage = <<EOS;
 Usage:
   --dbid        <numeric database id>
   --passphrase  <passphrase>
   --verbose
EOS

 print $usage;
    exit;
}

my $dbid;
my $passphrase;
my $verbose=0;

my $opts = GetOptions ("dbid=s" => \$dbid,
		       "passphrase=s" => \$passphrase,
		       "verbose" => \$verbose
    );

usage if !defined($dbid) && !defined($passphrase);

my $a = md5($passphrase);
my $a_bn = Crypt::OpenSSL::Bignum->new_from_hex(md5_hex($passphrase));
say "a ", md5_hex($passphrase) if $verbose;

# use dbid as exponent "p" 
my $p_bn = Crypt::OpenSSL::Bignum->new_from_decimal($dbid);
say "p ", $p_bn->to_decimal() if $verbose;

my $n_bn = Crypt::OpenSSL::Bignum->new_from_decimal("630331639550168233309051762056942870074475077630666125222716609316820293660708894656573328785087860438345075775189441098978632860949262920931693189212448293533142829156409699410426889957859310638041015450082276733831447358715155836261694043784600915176803949220910022723345745514918801050058651853815684706971693903305529430756480425118565838315867098072757477051310135674386514870213440520411392743649016707560589762060066573617237264575813655469838647793527447563193692895197873338614579769864274232196149888908975187340394877284711365203079426796144568440497760041991183943726872975711799509621926493267611744042912857596801436313010982071387912151436401007956164481790232775266449932102247682271531050853362603389302976254577420241791830299904027962768542753465664693702470535601941375311700180520909263342692407317934848207422338472634776160455895621679985546080040437911520741382035440601849997661014905231809522821826968760035980061717042506853518762129157896173430242868521243707445388837272280395577927039876253286758915446498930564510683222216418730656911016444673362005482249949222811313728218383096989372204428349869117188779850158771059508380422994486300516579667484479364111477671877882081794438223865563995725349820427");
say "n ", $n_bn->to_decimal() if $verbose;

# compute r = a ^ p mod n
my $ctx = Crypt::OpenSSL::Bignum::CTX->new();
my $r_bn = $a_bn->mod_exp($p_bn, $n_bn, $ctx);
say "r ", $r_bn->to_decimal() if $verbose;

# compute sha(r)
my $r_bin = $r_bn->to_bin;

# base64 encode sha224(r)
# note: sha224 is not supported by Perl. All exernal openssl.
umask 0400;
open FILE, "> $ENV{HOME}/.dbpass.bin" or die "Can not create $ENV{HOME}/.dbpass.bin";
binmode FILE;
print FILE $r_bin;
close FILE;
my $r2 = `openssl sha224 -binary $ENV{HOME}/.dbpass.bin`;
$r2 = encode_base64($r2);
$r2 = substr($r2, 0, 30);
say "r2 ", $r2 if $verbose;
unlink "$ENV{HOME}/.dbpass.bin";

# sanitize password
for (my $i = 1; $i <= 30; $i++)
{
    my $nth = substr($r2, $i-1, 1);
    # comply with Oracle password allowed chars
    substr($r2, $i-1, 1) = '_' if substr($r2, $i-1, 1) eq '/';
    substr($r2, $i-1, 1) = '_' if substr($r2, $i-1, 1) eq '+';
}

# 1st character of password must be uppercase alpha not a digit
    # if (r2_m_char[0] == '_')
    # 	r2_m_char[0] = 'A';
    # if (isdigit(r2_m_char[0]))
    # 	r2_m_char[0] = 'A' + (r2_m_char[0] - '0');
    # if (isalpha(r2_m_char[0]) && islower(r2_m_char[0]))
    # 	r2_m_char[0] = 'A' + (r2_m_char[0] - 'a');
substr($r2, 0, 1) = 'A' if substr($r2, 0, 1) eq '_';
substr($r2, 0, 1) = chr(ord('A') + ord(substr($r2, 0, 1)) - ord('0')) if substr($r2, 0, 1) =~/^[[:digit:]]$/;
substr($r2, 0, 1) = chr(ord('A') + ord(substr($r2, 0, 1)) - ord('a')) if substr($r2, 0, 1) =~/^[a-z]$/;

# # 2nd character of password must be lowercase alpha
    # if (r2_m_char[1] == '_')
    # 	r2_m_char[1] = 'a';
    # if (isdigit(r2_m_char[1]))
    # 	r2_m_char[1] = 'a' + (r2_m_char[1] - '0');
    # if (isalpha(r2_m_char[1]) && isupper(r2_m_char[1]))
    # 	r2_m_char[1] = 'a' + (r2_m_char[1] - 'A');
substr($r2, 1, 1) = 'a' if substr($r2, 1, 1) eq '_';
substr($r2, 1, 1) = chr(ord('a') + ord(substr($r2, 1, 1)) - ord('0')) if substr($r2, 1, 1) =~/^[[:digit:]]$/;
substr($r2, 1, 1) = chr(ord('a') + ord(substr($r2, 1, 1)) - ord('A')) if substr($r2, 1, 1) =~/^[A-Z]$/;

    # # 3rd character of password must be digit
    # if (!isdigit(r2_m_char[2]))
    # 	r2_m_char[2] = '0';    
substr($r2, 2, 1) = '0' if substr($r2, 2, 1) !~/^[[:digit:]]$/;

print $r2;

sub END {
    unlink "$ENV{HOME}/.dbpass.bin";
}

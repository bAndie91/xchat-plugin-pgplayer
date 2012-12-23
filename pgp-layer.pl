#!/usr/bin/env perl
#
#

use Data::Dumper;
use Xchat qw/EAT_NONE EAT_ALL EAT_XCHAT EAT_PLUGIN get_info command emit_print/;
use GnuPG;
use GnuPG::Tie::Encrypt;
use GnuPG::Tie::Decrypt;
use Time::HiRes qw/gettimeofday/;
use utf8;
sub yell { Xchat::print("\cC08".$_[0]); }


$VER = 0.2;
$auto_neg = 0;
$MAXMSGLEN = 400;	# 512 - length(overhead) # FIXME
# ignore keyring managers
/KEYRING/ and delete $ENV{$_}  for keys %ENV;
$GPG = new GnuPG();
@key_servers = qw{
	hkp://pgp.mit.edu
};


yell "loading PGP layer plugin.";
$gpg_header = "-----BEGIN PGP MESSAGE-----\n";
$gpg_tail = "\n-----END PGP MESSAGE-----";
%SESS = ();	# pgp encrypted dialog sessions
%PASS = ();	# passphrase(s) of own secret key(s)


Xchat::register("pgp-layer", $VER, "Pretty Good Privacy Layer under IRC", \&unload);

##push @Hooks, Xchat::hook_print("Server Connected", \&set_self_ident);
push @Hooks, Xchat::hook_command("QUERY", \&handshake_1);
##push @Hooks, Xchat::hook_print("Open Dialog", \&handshake_1);
push @Hooks, Xchat::hook_print("CTCP Send", \&nego_filter_1);
push @Hooks, Xchat::hook_print("CTCP Generic", \&handshake_2);
push @Hooks, Xchat::hook_print("Notice", \&handshake_3);
push @Hooks, Xchat::hook_print("Key Press", \&history);
push @Hooks, Xchat::hook_print("Your Message", \&cryptdata_filter);
push @Hooks, Xchat::hook_print("Your Action", \&cryptdata_filter);
push @Hooks, Xchat::hook_print("Private Message to Dialog", \&decrypt_filter);
#push @Hooks, Xchat::hook_print("Private Message", \&decrypt_filter);
push @Hooks, Xchat::hook_print("Change Nick", \&change_name);
push @Hooks, Xchat::hook_print("Your Nick Changing", \&change_name);
push @Hooks, Xchat::hook_command("PGP", \&ctl, {
	'help_text' => <<EOF
PGP SHOW    show your PGP identity
    IDENT [keyID] [passphrase]
            set your PGP identity by secret GPG key,
            default key is the first one on your keyring
    AUTO    enable auto negotiation when QUERY somebody
    START   initialize PGP session manually
    STOP    close session, switch back to cleartext
    DUMP    print plugin data to stderr
    SEND    internal use
EOF
		});



sub key_exists {
	my $keyid = shift;
	my $secret = shift || 0;
	open IN, '>';
	open OUT;
	pipe OUT, IN;
	$GPG->export_keys( 'keys' => $keyid, 'secret' => $secret, 'output' => \*IN );
	close IN;
	local $/ = undef;
	my $export = <OUT>;
	close OUT;
	return $keyid if $export ne '';
	return undef;
}
sub context_type {
	for(Xchat::get_list('channels')) {
		if($_->{'network'} eq $_[1] and $_->{'channel'} eq $_[0]) {
			return $_->{'type'};
		}
	}
	return undef;
}

sub gpg_key_list {
	my $type = $_[0];
	return (gpg_key_list(0), gpg_key_list(1))  if($type == 2);

	my $keyid, $created, $comment, $email, $realname, $expires;
	my @list;
	
	open LIST, '-|', $GPG->{'gnupg_path'}, '--list'.($type==1?'-secret':'').'-keys', '--no-tty'   or return undef;
	while(<LIST>) {
		if( /^(?:sec|pub)\s+.*?\/([0-9A-F]+)\s+([0-9\/\.-]+)/ ) {
			$keyid = $1;
			$created = $2;
			if( /expires:\s*([0-9\/\.-]+)/ ) {
				$expires = $1;
			}
		}
		elsif( /^uid\s+([^(<]+)(?:\((.*?)\)\s+)?(?:\<(.*?)\>)?/ ) {
			$comment = $2;
			$email = $3;
			$realname = $1;
			$realname =~ s/\s*$//;
		}
		if(defined $keyid and defined $realname) {
			push @list, {'keyid'=>$keyid, 'created'=>$created, 'realname'=>$realname, 'comment'=>$comment, 'email'=>$email, 'expires'=>$expires};
			$keyid = $created = $comment = $email = $realname = $expires = undef;;
		}
	}
	close LIST;
	return @list
}
sub passphrase_dialog {
	my ($title, $text) = (shift, shift);
	open ZENITY, '-|', qq{ zenity --title="$title" --entry --hide-text --text="$text" };
	my $_ = <ZENITY>;
	close ZENITY;
	s/\r?\n$//;
	return $_;
}

sub set_self_ident {
	my $network = get_info('network');
	my $nick = get_info('nick');
	my $keyname = shift;
	my @priv_ring = gpg_key_list(1);
	my %priv_ring_by_email = map { $_->{'email'} => $_ } @priv_ring;
	my %priv_ring_by_keyid = map { $_->{'keyid'} => $_ } @priv_ring;
	my %details = ();

	if(not $keyname) {
		# use secret key if defined on other network
		N:for$N(keys %SESS) {
		    for(keys %{$SESS{$N}}) {
			if($SESS{$N}->{$_}->{'own'}) {
				%details = %{$priv_ring_by_keyid{ $SESS{$N}->{$_}->{'key_id'} }};
				last N;
			}
		    }
		}
		if(scalar(keys%details)<1 and scalar(@priv_ring)>0) {
			# default secret key is 1st on keyring
			%details = %{$priv_ring[0]};
		}
	}
	elsif($keyname =~ /^[0-9A-F]{8}$/  and  defined $priv_ring_by_keyid{$keyname}) {
		%details = %{$priv_ring_by_keyid{$keyname}};
	}
	elsif(defined $priv_ring_by_email{$keyname}) {
		%details = %{$priv_ring_by_email{$keyname}};
	}
	if(scalar(keys%details)<1) {
		yell "Error: secret key unavailable.";
		return EAT_NONE;
	}

	my $mykeyid = $details{'keyid'};
	my $realname = $details{'realname'};
	my $email = $details{'email'};

	
	my $pass = shift || $PASS{$mykeyid} || passphrase_dialog("GPG Passphrase", "Enter passphrase for secret key 0x$mykeyid ($realname <$email>)");
	if( test_secret_key($mykeyid, $pass) ) {
		if( defined $SESS{$network}->{$nick}->{'key_id'} and $mykeyid ne $SESS{$network}->{$nick}->{'key_id'} ) {
			for(keys %{$SESS{$network}}) {
				# drop encrypt-buffers for the old private key
				delete $SESS{$network}->{$_}->{'decrypt_buffer'};
				# fresh key ID on live sessions
				Xchat::command("NCTCP $_ PGPLAYER $VER KEYID=$mykeyid")  if $SESS{$network}->{$_}->{'key_id'};
			}
		}
		$SESS{$network}->{$nick}->{'key_id'} = $mykeyid;
		$SESS{$network}->{$nick}->{'own'} = 1;
		$PASS{$mykeyid} = $pass;
		yell "Identity changed: 0x$mykeyid - $realname <$email>";
	} else {
		yell "Can not use this key. (Wrong passphrase?)";
	}

	return EAT_NONE;
}
sub handshake_1 {
	# Offer PGP layer establishment
	
	if( $SESS{get_info('network')}->{get_info('nick')}->{'key_id'} ) {
		my $partner = $_[0][1];
		if($auto_neg) {
			Xchat::command("CTCP $partner PGPLAYER");
		}
	}
	return EAT_NONE;
}
sub nego_filter_1 {
	return EAT_ALL  if $_[0][1] =~ /^PGPLAYER\b/;
	return EAT_NONE;
}
sub handshake_2 {
	# Reply PGP negotiation and ask back

	my $ctcp_type = $_[0][0];
	if($ctcp_type eq 'PGPLAYER') {
		my $partner = $_[0][1];
		my $network = get_info('network');
		my $mykeyid = $SESS{$network}->{get_info('nick')}->{'key_id'};
		if($mykeyid) {
			command("NCTCP $partner PGPLAYER $VER KEYID=$mykeyid");
			if(not $SESS{$network}->{$partner}->{'key_id'} and $SESS{$network}->{$partner}->{'last_missing_pubkey_time'}<time-5) {
				command("CTCP $partner PGPLAYER");
			}
		}
		else {
			Xchat::set_context($partner);
			yell "PGP session requested by $partner, but no secret key defined. Type /PGP IDENT [keyID] [passphrase]";
		}
		return EAT_ALL;
	}
	return EAT_NONE;
}
sub handshake_3 {
	# Receive PGP negotiation answer, search for public keys

	my $partner = $_[0][0];
	my $network = get_info('network');
	my $_ = $_[0][1];
	if(/^PGPLAYER (\S+)/) {
		my $remote_ver = $1;
		if( $remote_ver == 0 ) {
			delete $SESS{$network}->{$partner};
			yell "PGP session closed with $partner";
			return EAT_ALL;
		}
		if( /\sKEYID=([A-F0-9]+)/ ) {
			my $partner_key_id = $1;
			$SESS{$network}->{$partner}->{'ver'} = $remote_ver;
			
			my %detail = map { $_->{'keyid'} => $_ } gpg_key_list(0);
			if( exists $detail{$partner_key_id} ) {
				my $realname = $detail{$partner_key_id}->{'realname'};
				my $email = $detail{$partner_key_id}->{'email'};
			
				$SESS{$network}->{$partner}->{'key_id'} = $partner_key_id;
				yell "PGP encrypted session initialized with $partner ($realname <$email>, 0x$partner_key_id)";
			} else {
				$SESS{$network}->{$partner}->{'key_id'} = undef;
				$SESS{$network}->{$partner}->{'last_missing_pubkey_time'} = time;
				yell "You haven't $partner"."'s public key: 0x$partner_key_id";
				# FIXME: fetch...
			}
			return EAT_ALL;
		}
	}
	return EAT_NONE;
}


sub history {
	my $keycode = $_[0][0];
	my $modifier = $_[0][1];
	my $char = $_[0][2];
	my $inputbox = get_info("inputbox");

	if(($modifier & 13) == 0) {
		# Enter key, not command
		if($char eq "\r" and $inputbox =~ /^([^\/]|\/me\s)/i) {
		  
		  	# Rewrite entered message text (or /ME action)
			if( $SESS{get_info('network')}->{get_info('channel')}->{'key_id'} ) {
				command("SETTEXT /PGP SEND $inputbox");
			}
		}
		# Up/Down key
		elsif($keycode == 65364 or $keycode == 65362) {
		
			# Replace back to original string when browsing the input history
			Xchat::Internal::unhook($replacetimer);
			$replacetimer = Xchat::hook_timer(3, sub {
				if(get_info("inputbox") =~ /^\/PGP SEND /) {
					my $text = $';
					command("SETTEXT $text");
					command("SETCURSOR ".length($text));
				}
				return Xchat::REMOVE;
			});
		}
	}
	return EAT_NONE;
}


sub gpg_encrypt {
	# arg 1 - string to be encrypted
	# arg 2 - encrypt for this user
	# arg 3 - sign by this key - OPTIONAL
	# arg 4 - passphrase for signing key - OPTIONAL
	
	my $cleartext = shift;
	my $recipient_keyid = shift;
	my $network = get_info('network');
	my $mykeyid = shift || $SESS{$network}->{get_info('nick')}->{'key_id'};
	my $pass = shift || $PASS{$mykeyid};
	my $ts0 = scalar gettimeofday;
	
	my $ciphertext = eval q{
		tie *CIPHER, 'GnuPG::Tie::Encrypt', 
			armor => 1, recipient => $recipient_keyid, sign => 1, 'local-user' => $mykeyid, passphrase => $pass;
		my $cleartext = $cleartext;
		utf8::encode($cleartext);
		print CIPHER $cleartext;
		local $/ = undef;
		my $ciphertext = <CIPHER>;
		close CIPHER;
		untie *CIPHER;
		$ciphertext;
	};
	my $ts = scalar(gettimeofday)-$ts0;
	print STDERR Dumper $cleartext, $ciphertext, $@   if $DEBUG;

	$ciphertext =~ s/^.*?(\r?\n\r?\n)//s;
	$ciphertext =~ s/----.*$//s;
	$ciphertext =~ s/[\r\n]//g;
	
	my $ovrh = length($ciphertext)*100/length($cleartext) - 100;
	print STDERR sprintf("encrypt time = %.2f sec\noverhead = %.0f%%\n", $ts, $ovrh)   if $DEBUG;
	return $ciphertext;
}
sub gpg_decrypt {
	my $ciphertext = shift;
	my $ciphertext_len = length $ciphertext;
	my $mykeyid = $SESS{get_info('network')}->{get_info('nick')}->{'key_id'};
	
	$ciphertext =~ s/.{64}/$&\n/g;
	$ciphertext =~ s/=[^=]+$/\n$&/;
	$ciphertext = $gpg_header.$ciphertext.$gpg_tail;
	my $ts0 = scalar gettimeofday;
	
	my $cleartext = eval q{
		tie *PLAINTEXT, 'GnuPG::Tie::Decrypt', passphrase => $PASS{$mykeyid};
		print PLAINTEXT $ciphertext;
		local $/ = undef;
		my $cleartext = <PLAINTEXT>;
		close PLAINTEXT;
		untie *PLAINTEXT;
		utf8::decode($cleartext);
		$cleartext;
	};
	my $ts = scalar(gettimeofday)-$ts0;
	
	print STDERR Dumper $ciphertext, $cleartext, $@   if $DEBUG;
	# FIXME: verify sign
		
	my $ovrh = $ciphertext_len*100/length($cleartext) - 100   unless $cleartext eq '';
	print STDERR sprintf("decrypt time = %.2f sec\noverhead = %.0f%%\n", $ts, $ovrh)   if $DEBUG;
	return $cleartext;
}

sub test_secret_key {
	return gpg_encrypt(rand(100), $_[0], $_[0], $_[1]);
}

sub partitize {
	my $_ = shift;
	my $length = shift;
	my @slices = ();
	push @slices, $&."\\"  while s/.{$length}//;
	push @slices, $_;
	print STDERR "slices = ".scalar(@slices)."\n"   if $DEBUG;
	return @slices;
}

sub cryptdata_filter {
	return EAT_ALL if $SESS{get_info('network')}->{get_info('channel')}->{'speaking_base64'};
	return EAT_NONE;
}
sub decrypt_filter {
	my $network = get_info('network');
	my $partner = $_[0][0];
	return EAT_NONE unless $SESS{$network}->{$partner}->{'key_id'};
	
	my $msg = $_[0][1];
	my $partial = $msg =~ s/\\$//;
	push @{$SESS{$network}->{$partner}->{'decrypt_buffer'}}, $msg;
	return EAT_ALL if $partial;
	
	my $buf = join '', @{$SESS{$network}->{$partner}->{'decrypt_buffer'}};
	print STDERR "slices = ".scalar(@{$SESS{$network}->{$partner}->{'decrypt_buffer'}})."\n"   if $DEBUG;
	my $decrypted = gpg_decrypt $buf;
	@{$SESS{$network}->{$partner}->{'decrypt_buffer'}} = ();
	if(defined $decrypted) {
		if($decrypted =~ s/^\/me\s+//) {
			emit_print("Private Action to Dialog", $partner, $decrypted);
		} else {
			emit_print("Private Message to Dialog", $partner, $decrypted);
		}
	}
	else {
		yell "Can not decrypt following line:\cC $buf";
		yell "Type /PGP STOP to hang up decrypting.";
	}
	return EAT_ALL;
}

sub ctl {
	$_ = lc $_[0][1];
	my $network = get_info('network');
	my $partner = get_info('channel');
	my $nick = get_info('nick');
	if(/^dump$/) {
		print STDERR Dumper {"Auto negotiation"=>$auto_neg, "Max message length"=>$MAXMSGLEN, "Debugging"=>$DEBUG}, \%SESS;
	}
	elsif(/^ident$/) {
		set_self_ident($_[0][2], $_[1][3]);
	}
	elsif(/^show$/) {
		my $keyid = $SESS{$network}->{$nick}->{'key_id'};
		if($keyid) {
			my %detail = map { $_->{'keyid'} => $_ } gpg_key_list(2);
			my $realname = $detail{$keyid}->{'realname'};
			my $email = $detail{$keyid}->{'email'};
			yell "You are using secret key 0x$keyid - $realname <$email> - for GPG encryption and signing.";
			if( $keyid = $SESS{$network}->{$partner}->{'key_id'} ) {
				$realname = $detail{$keyid}->{'realname'};
				$email = $detail{$keyid}->{'email'};
				yell "Conversation with $partner - $realname <$email>, 0x$keyid - is encrypted and verified.";
			}
		} else {
			yell "PGP unconfigured on this network. Enter /PGP IDENT [keyID] [passphrase]";
		}
	}
	elsif(/^auto$/) {
		$auto_neg = 1;
	}
	elsif(/^start$/) {
		set_self_ident($_[0][2], $_[1][3])  unless $SESS{$network}->{$nick}->{'key_id'};
		if($SESS{$network}->{$nick}->{'key_id'}) {
			if(context_type($partner, $network) == 3) {
				# offering PGP session to a user (type 3)
				Xchat::command("CTCP $partner PGPLAYER");
			} else {
				yell "Session can be establish only with individual users.";
			}

		}
	}
	elsif(/^stop$/) {
		delete $SESS{$network}->{$partner};
		yell "PGP session closed with $partner";
		Xchat::command("NCTCP $partner PGPLAYER 0");
	}
	elsif(/^(no)?debug$/) {
		$DEBUG = $1 ? 0 : 1;
	}
	elsif(/^send$/) {
		my $msgtext = $_[1][2];
		my @encrypted = partitize ( gpg_encrypt ($msgtext, $SESS{$network}->{$partner}->{'key_id'}), $MAXMSGLEN );
		$SESS{$network}->{$partner}->{'speaking_base64'} = 1;
		command("SAY $_") for @encrypted;
		$SESS{$network}->{$partner}->{'speaking_base64'} = 0;
		if($msgtext =~ s/^\/me\s+//i) {
			emit_print("Your Action", get_info('nick'), $msgtext);
		} else {
			emit_print("Your Message", get_info('nick'), $msgtext);
		}
	}
	else {
		yell "IDENT, SHOW, AUTO, START, STOP, DUMP, DEBUG, NODEBUG";
	}
	return EAT_ALL;
}

sub change_name {
	# update SESSion keys when sbdy changes his/her nick
	my $old = $_[0][0];
	my $new = $_[0][1];
	my $network = get_info('network');
	if(defined $SESS{$network}->{$old}) {
		$SESS{$network}->{$new} = $SESS{$network}->{$old};
		delete $SESS{$network}->{$old};
	}
	return EAT_NONE;
}

sub unload {
	# FIXME: save preferences
	my ($channel, $server) = (get_info('channel'), get_info('server'));	# set_context() takes server, not network.
	for(Xchat::get_list('channels')) {
		%_ = %$_;
		if(defined $SESS{$_{'network'}}->{$_{'channel'}}->{'key_id'}) {
			Xchat::set_context($_{'channel'}, $_{'server'});
			yell "PGP session closed with $_{'channel'}";
		}
	}
	Xchat::set_context($channel, $server);
	Xchat::Internal::unhook($_) for @Hooks;
	return 1;
}


__END__


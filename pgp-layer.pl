#!/usr/bin/env perl
#
#

use Data::Dumper;
use Xchat qw/EAT_NONE EAT_ALL EAT_XCHAT EAT_PLUGIN get_info command emit_print set_context strip_code/;
use GnuPG;
use GnuPG::Tie::Encrypt;
#use GnuPG::Tie::Decrypt;
use Time::HiRes qw/gettimeofday/;
use utf8;
use YAML qw/DumpFile LoadFile/;
sub yell { Xchat::print("\cC08".$_[0]); }


$VER = '0.8';
@xchat_ver = split/\./, get_info('version');
yell "loading PGP layer plugin ver $VER";

$conf_file = get_info('xchatdir')."/pgp-layer.yaml";
if(-r $conf_file) {
	$Pref_ref = LoadFile($conf_file);
	%Pref = %$Pref_ref   if ref $Pref_ref eq 'HASH';
}
%Defaults = (
	'MAXMSGLEN' => 400,	# 512 - length(overhead) # FIXME
	'DEBUG' => 0,
	'auto_neg' => 0,
	'PrependChrs' => '',	# prepend this chars (usually color and format codes) for encrypted messages
	'ModeChr' => ':',	# UMODE char indicating pgp-layed message
	'key_servers' => [qw{
		hkp://pgp.mit.edu
	}],
	'menuindicator' => 0,
	'indicator' => 0,
	'tabindicator' => 1,
);
for(keys%Defaults) { $Pref{$_} = $Defaults{$_} unless exists $Pref{$_} }
$gpg_header = "-----BEGIN PGP MESSAGE-----\n";
$gpg_tail = "\n-----END PGP MESSAGE-----";


# ignore keyring managers
/KEYRING|GPG_AGENT/ and delete $ENV{$_}  for keys%ENV;
$GPG = new GnuPG();
%SESS = ();	# pgp encrypted dialog sessions
%PASS = ();	# passphrase(s) of own secret key(s)


Xchat::register("pgp-layer", $VER, "Pretty Good Privacy Layer under IRC", \&unload);

push @Hooks, Xchat::hook_command("QUERY", \&handshake_1);
push @Hooks, Xchat::hook_print("CTCP Send", \&nego_filter_1);
push @Hooks, Xchat::hook_print("CTCP Generic", \&handshake_2);
push @Hooks, Xchat::hook_print("Notice", \&handshake_3);
push @Hooks, Xchat::hook_print("Key Press", \&history);
push @Hooks, Xchat::hook_print("Focus Tab", \&indicator_wrapper);
push @Hooks, Xchat::hook_print("Your Message", \&cryptdata_filter);
push @Hooks, Xchat::hook_print("Your Action", \&cryptdata_filter);
push @Hooks, Xchat::hook_print("Private Message to Dialog", \&decrypt_filter);
push @Hooks, Xchat::hook_print("Change Nick", \&change_name);
# FIXME on exit close sess.
push @Hooks, Xchat::hook_print("Your Nick Changing", \&change_name);
$Help = <<EOF
PGP <command> [parameters]
 SHOW [IDENT|COLOR|STAT]
        show your and peer's identity, color & formatting of pgp-layed messages
        and statictics
 IDENT [keyID] [passphrase]
        change your PGP identity by secret GPG key, put "-" as keyID to drop your
        identity, omit passphrase to get a prompt for it
 [NO]AUTO       disable/enable auto negotiation when you QUERY somebody
 INDIC [MENU | FAKE | TAB | NO]
        set status indicator to be shown
        MENU: in main menu
        FAKE: as fake text in input field,
        TAB: on tab's label
        NO: disable all
 START          initialize PGP session with a user
 STOP           close session, switch back to cleartext
 COLOR <code>   set format and color codes encrypted messages are colored and 
                formatted with
 CHAR <chr>     set UMODE char for pgp-layed messages (default ':')
 DUMP           print debug data to stderr
 [NO]DEBUG      print debug data next to messages
 SEND           internal use
http://code.google.com/p/xchat-plugin-pgplayer/wiki/Usage
EOF
;
push @Hooks, Xchat::hook_command("PGP", \&ctl, { 'help_text' => $Help });



sub save_pref {
	return DumpFile($conf_file, \%Pref);
}
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
	my $gettype = $_[0];
	return (gpg_key_list(0), gpg_key_list(1))  if($gettype == 2);

	my $keyid, $created, $comment, $email, $realname, $expires;
	my @list;
	
	open LIST, '-|', $GPG->{'gnupg_path'}, '--list'.($gettype==1?'-secret':'').'-keys', '--with-colon', '--no-tty', '--lock-never'   or return undef;
	while(<LIST>) {
		my ($type, $trust, $length, $algo, $keyid, $created, $expires, $any, $any, $userdata, $any) = split ':', $_;
		next unless $type =~ /^sec|pub$/;

		$userdata =~ s/\\x([[::xdigit]]{2})/chr(hex$1)/ige;
		$userdata =~ /([^(<]+)(?:\((.*?)\)\s+)?(?:\<(.*?)\>)?/;
		   $comment = $2;
		   $email = $3;
		   $realname = $1;
		   $realname =~ s/\s*$//;
		
		push @list, {'keyid'=>$keyid, 'created'=>$created, 'realname'=>$realname, 'comment'=>$comment, 'email'=>$email, 'expires'=>$expires||undef};
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
	
	if($keyname eq '-') {
		delete $SESS{$network}->{$nick};
		for(keys %{$SESS{$network}}) {
			# close session with partners
			command("NCTCP $_ PGPLAYER 0")  if $SESS{$network}->{$_}->{'key_id'};
			delete $SESS{$network}->{$_}->{'key_id'};
			yell "PGP session closed with $_";
		}
		return EAT_NONE;
	}
	
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
	elsif($keyname =~ /^(?:0x)?([0-9A-Fa-f]{16})$/  and  $keyname = uc$1  and  defined $priv_ring_by_keyid{$keyname}) {
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

	
	my $pass = $_[0] || $PASS{$mykeyid} || passphrase_dialog("GPG Passphrase", "Enter passphrase for secret key 0x$mykeyid ($realname <$email>)");
	if( test_secret_key($mykeyid, $pass) ) {
		if( defined $SESS{$network}->{$nick}->{'key_id'} and $mykeyid ne $SESS{$network}->{$nick}->{'key_id'} ) {
			for(keys %{$SESS{$network}}) {
				# drop encrypt-buffers for the old private key
				delete $SESS{$network}->{$_}->{'decrypt_buffer'};
				# fresh key ID on live sessions
				command("NCTCP $_ PGPLAYER $VER KEYID=$mykeyid")  if $SESS{$network}->{$_}->{'key_id'};	# comment out to hide when you change your sign
			}
		}
		$SESS{$network}->{$nick}->{'key_id'} = $mykeyid;
		$SESS{$network}->{$nick}->{'own'} = 1;
		$PASS{$mykeyid} = $pass;
		yell "Identity changed: 0x$mykeyid - $realname <$email>";
	} else {
		unless($_[0]) { delete $PASS{$mykeyid}; }  # drop stored passphrase if it (may) used in "my$pass=..." (ie. no passphrase argument given) and it was wrong
		yell "Can not use this key. (Wrong passphrase?)";
	}

	return EAT_NONE;
}
sub handshake_1 {
	# Offer PGP layer establishment
	
	if( $SESS{get_info('network')}->{get_info('nick')}->{'key_id'} and $Pref{'auto_neg'} ) {
		my $partner = $_[0][1];
		command("CTCP $partner PGPLAYER");
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
			my $switched = set_context($partner);
			yell "PGP session requested by $partner, but no secret key defined. Type /PGP ".($switched?"START":"IDENT")." [keyID] [passphrase]";
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
				yell "PGP encrypted session initialized with $partner - $realname <$email>, 0x$partner_key_id";
			} else {
				$SESS{$network}->{$partner}->{'key_id'} = undef;
				$SESS{$network}->{$partner}->{'last_missing_pubkey_time'} = time;
				yell "You haven't $partner\x27s public key: 0x$partner_key_id";
				# FIXME: fetch from keyserver, check fingerprints, set trust level
			}
			return EAT_ALL;
		}
		
	# Receive delivery ACKnowladge
	
		elsif(/\sACK\b/) {
			if(set_context $partner) {
				indicator($SESS{$network}->{$partner}->{'receive'}, --$SESS{$network}->{$partner}->{'transmit'});
			}
			return EAT_ALL;
		}
	}
	return EAT_NONE;
}


sub escape {
	my $_ = ${$_[0]};
	s/\\/\\\\/g;
	s/\n/\\n/g;
	s/\r/\\r/g;
	${$_[0]} = $_;
}
sub unescape {
	my $_ = ${$_[0]};
	s/\\r/\r/g;
	s/\\n/\n/g;
	s/\\\\/\\/g;
	${$_[0]} = $_;
}
sub history {
	my $keycode = $_[0][0];
	my $modifier = $_[0][1];
	my $char = $_[0][2];
	my $inputbox = get_info("inputbox");

	if($inputbox =~ /^(\[(receive,transmit|receive|transmit)\.{3}\] |)/) {
	    my $L = length($&);
	    if($keycode == 65360 or $keycode == 65361) {
		# Home/Left key pressed and there is transreceive indicator
		Xchat::Internal::unhook($fakehometimer);
		$fakehometimer = Xchat::hook_timer(1, sub {
			# FIXME: It clears text selection.
			command("SETCURSOR ".$_[0]) if get_info('state_cursor') < $_[0];
			return Xchat::REMOVE;
		}, { 'data' => $L });
	    }
	    elsif($keycode == 65288) {
	    	return EAT_ALL if get_info('state_cursor') <= $L;
	    }
	}
	if(($modifier & 13) == 0) {
		$inputbox =~ s/^\[(receive,transmit|receive|transmit)\.{3}\] //;
		
		# Enter key pressed and there is not a command
		if($char eq "\r") {
		    if($inputbox =~ /^([^\/]|\/me\s)/i) {
		  
		  	# Rewrite entered message text (or /ME action)
			if( $SESS{get_info('network')}->{get_info('channel')}->{'key_id'} ) {
				escape \$inputbox;
				command("SETTEXT /PGP SEND $inputbox");
			}
		    }
		    else {
			command("SETTEXT $inputbox");
			Xchat::Internal::unhook($indi3timer);
			$indi3timer = Xchat::hook_timer(5, sub {
				my ($n, $c) = (get_info('network'), get_info('channel'));
				indicator($SESS{$n}->{$c}->{'receive'}, $SESS{$n}->{$c}->{'transmit'});
				return Xchat::REMOVE;
			});
		    }
		}
		# Up/Down key
		elsif($keycode == 65364 or $keycode == 65362) {
		
			# Replace back to original string when browsing the input history
			Xchat::Internal::unhook($replacetimer);
			$replacetimer = Xchat::hook_timer(1, sub {
				if(get_info('inputbox') =~ /^\/PGP SEND /) {
					my $text = $';
					unescape \$text;
					command("SETTEXT $text");
					command("SETCURSOR ".length($text));
				}
				return Xchat::REMOVE;
			});
		}
	}
	return EAT_NONE;
}
sub indicator {
	my @indicatee;
	push @indicatee, "receive"   if $_[0];
	push @indicatee, "transmit"  if $_[1];

	if( $Pref{'indicator'} ) {	
		my $_ = get_info('inputbox');
		s/^(\[(receive,transmit|receive|transmit)\.{3}\] |)//;
		my $cp = get_info('state_cursor') - length($&);
		$cp = 0 if $cp < 0;
		my $new = (scalar @indicatee) ? "[".join(',', @indicatee)."...] " : '';
		$cp += length($new);
		
		command("SETTEXT $new$_");
		command("SETCURSOR $cp");
	}
	if( $Pref{'menuindicator'} ) {
		my %a = %{ $SESS{get_info('network')}->{get_info('channel')} };
		for my $s (qw/receive transmit/) {
		    command("MENU DEL \"$s...\"");
		    command("MENU DEL \"$s\"");
		    if($a->{'key_id'}) {
		    	if(grep {$s eq $_} @indicatee) {
		    		my $label = "$s...";
		    		$label = "<b>$s...<\x03b>" if($xchat_ver[0]>=2 and $xchat_ver[1]>=6 and $xchat_ver[2]>=6);
				command("MENU -m ADD \"$label\"");
		    	} else {
				command("MENU -e0 ADD \"$s\"");
		    	}
		    }
		}
	}
	if( $Pref{'tabindicator'} ) {
		my $labelpre = (scalar @indicatee) ? "[".join(',', map {/./;$&} @indicatee)."] " : '';
		command("SETTAB ".$labelpre.get_info('channel'));
	}
}
sub indicator_wrapper {
	my %a = %{ $SESS{get_info('network')}->{get_info('channel')} };
	indicator($a{'receive'}, $a{'transmit'});
	return EAT_NONE;
}


sub gpg_encrypt {
	# arg 1 - string to be encrypted
	# arg 2 - encrypt for this user
	# arg 3 - sign by this key - OPTIONAL
	# arg 4 - passphrase for signing key - OPTIONAL
	# arg 5 - reference to a scalar decrypt time stored in - OPTIONAL
	
	my $cleartext = shift;
	my $recipient_keyid = shift;
	my $network = get_info('network');
	my $mykeyid = shift || $SESS{$network}->{get_info('nick')}->{'key_id'};
	my $pass = shift || $PASS{$mykeyid};
	my $ts_ref = shift;
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
	$$ts_ref = $ts   if ref $ts_ref eq 'SCALAR';
	print STDERR Dumper $cleartext, $ciphertext, $@   if $Pref{'DEBUG'};

	$ciphertext =~ s/^.*?(\r?\n\r?\n)//s;
	$ciphertext =~ s/----.*$//s;
	$ciphertext =~ s/[\r\n]//g;
	
	my $ovrh = length($ciphertext)*100/length($cleartext) - 100;
	print STDERR sprintf("encrypt time = %.2f sec\noverhead = %.0f%%\n", $ts, $ovrh)   if $Pref{'DEBUG'};
	return $ciphertext;
}
sub gpg_decrypt {
	my $ciphertext = shift;
	my $ciphertext_len = length $ciphertext;
	my $mykeyid = $SESS{get_info('network')}->{get_info('nick')}->{'key_id'};
	my $ts_ref = shift;
	my $sign_result_ref = shift;
	
	$ciphertext =~ s/=[^=]+$/\n$&/;
	$ciphertext =~ s/.{64}/$&\n/g;
	$ciphertext = $gpg_header.$ciphertext.$gpg_tail;
	my $ts0 = scalar gettimeofday;
	
	my $cleartext = eval q{
		open CIPIN, '>';	open CIPOUT;
		open CLRIN, '>';	open CLROUT;
		pipe CIPOUT, CIPIN;	pipe CLROUT, CLRIN;
		print CIPIN $ciphertext;close CIPIN;
		$ref = $GPG->decrypt( 'ciphertext' => \*CIPOUT, 'output' => \*CLRIN, 'passphrase' => $PASS{$mykeyid} );
		close CIPOUT;		close CLRIN;
		local $/ = undef;
		my $cleartext = <CLROUT>;
		close CLROUT;
		utf8::decode($cleartext);
		$cleartext;
	};
	my $ts = scalar(gettimeofday)-$ts0;
	$$ts_ref = $ts   if ref $ts_ref eq 'SCALAR';
	
	print STDERR Dumper $ciphertext, $cleartext, \%$ref, $@   if $Pref{'DEBUG'};
	my $ovrh = $ciphertext_len*100/length($cleartext) - 100   unless $cleartext eq '';
	print STDERR sprintf("decrypt time = %.2f sec\noverhead = %.0f%%\n", $ts, $ovrh)   if $Pref{'DEBUG'};
	
	%$sign_result_ref = %$ref   if ref $ref eq 'HASH';
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
	print STDERR "slices = ".scalar(@slices)."\n"   if $Pref{'DEBUG'};
	return @slices;
}

sub cryptdata_filter {
	return EAT_ALL if $SESS{get_info('network')}->{get_info('channel')}->{'speaking_base64'};
	return EAT_NONE;
}
sub decrypt_filter {
	my $network = get_info('network');
	my $partner = strip_code($_[0][0]);
	return EAT_NONE unless $SESS{$network}->{$partner}->{'key_id'};
	
	my $msg = $_[0][1];
	my $partial = $msg =~ s/\\$//;
	my $buff_ref = \@{$SESS{$network}->{$partner}->{'decrypt_buffer'}};
	push @$buff_ref, $msg;
	if(1 == scalar @$buff_ref) {
		$SESS{$network}->{$partner}->{'slice0_time'} = scalar(gettimeofday);
		$SESS{$network}->{$partner}->{'receive'}++;
	}
	if($partial) {
		indicator($SESS{$network}->{$partner}->{'receive'}, $SESS{$network}->{$partner}->{'transmit'});
		return EAT_ALL;
	}

	my $t = scalar(gettimeofday);
	command("NCTCP $partner PGPLAYER $VER ACK");
	indicator(--$SESS{$network}->{$partner}->{'receive'}, $SESS{$network}->{$partner}->{'transmit'});
	
	my $flood_delay = $t - $SESS{$network}->{$partner}->{'slice0_time'};
	shift @d_fld  if scalar @d_fld >= 5;
	push @d_fld, $flood_delay;
	my $slices = scalar @$buff_ref;
	print STDERR Dumper "slices", \@$buff_ref, sprintf("flood delay = %.2f sec", $flood_delay)    if $Pref{'DEBUG'};
	my $t_dec;
	my %sign_result;

	my $buf = join '', @$buff_ref;
	my $decrypted = gpg_decrypt($buf, \$t_dec, \%sign_result);
	@$buff_ref = ();

	my $Append = $Pref{'DEBUG'} ? sprintf("\cO \cB\cC02[\cO\cC15slc=%d; d_fld=%.2f; t_dec=%.2f; age=%.2f\cB\cC02]", $slices, $flood_delay, $t_dec, $t - $sign_result{'timestamp'}) : '';

	if($sign_result{'keyid'} ne $SESS{$network}->{$partner}->{'key_id'}) {
		$Append .= $Pref{'DEBUG'} ? " \cO\cC15".($sign_result{'keyid'} ? ("signed by \cB".$sign_result{'user'}."\cB, 0x".$sign_result{'keyid'}) : "sign not known") : '';
		for(split /\n/, $decrypted) {
			emit_print("Private Message to Dialog", '3rd_person', "\cC05\cBWARNING:\cB \037Sign mismatch\cO ".$Pref{'PrependChrs'}.$_.$Append, $Pref{'ModeChr'});
			undef $Append;
		}
	}
	elsif(defined $decrypted) {
		if($decrypted =~ s/^\/me\s+//) {
			for(split /\n/, $decrypted) {
				emit_print("Private Action to Dialog", $partner, $Pref{'PrependChrs'}.$_.$Append, $Pref{'ModeChr'});
				undef $Append;
			}
		} else {
			for(split /\n/, $decrypted) {
				emit_print("Private Message to Dialog", $partner, $Pref{'PrependChrs'}.$_.$Append, $Pref{'ModeChr'});
				undef $Append;
			}
		}
	}
	else {
		yell "Can not decrypt following datagramm:\cC $buf";
		yell "Type /PGP STOP to hang up.";
	}
	return EAT_ALL;
}

sub ctl {
	$_ = lc $_[0][1];
	my $network = get_info('network');
	my $partner = get_info('channel');
	my $nick = get_info('nick');
	if(/^dump$/) {
		print STDERR Dumper \%Pref, \%SESS;
	}
	elsif(/^ident$/) {
		set_self_ident($_[0][2], $_[1][3]);
	}
	elsif(/^show$/) {
		my $subcmd = lc $_[0][2];
		if($subcmd=~/^ident/ or not $subcmd) {
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
			yell "PGP is unconfigured on this network. Enter /PGP IDENT [keyID] [passphrase]";
		    }
		}
		if($subcmd=~/^colou?r/ or not $subcmd) {
		    emit_print("Private Message to Dialog", "pgp_plugin", $Pref{'PrependChrs'}."Encrypted messages look like this.", $Pref{'ModeChr'});
		}
		if(($subcmd=~/^stat/ or not $subcmd) and $cnt = scalar(@d_fld)) {
		    Xchat::print("Flood delay of last $cnt messages: ".
		    	join(' ', map {sprintf"%.2f",$_} @d_fld).
		    	"; avg: ".do{
		    		my $sum;
		    		$sum += $_ for @d_fld;
		    		sprintf "%.2f", $sum / $cnt;
		    	});
		}
	}
	elsif(/^(no)?auto$/) {
		$Pref{'auto_neg'} = $1 ? 0 : 1;
		save_pref;
	}
	elsif(/^indi/) {
		while($_[0][2]) {
		    if($_[0][2] =~ /^fake/i) {
			$Pref{'indicator'} = 1; }
		    elsif($_[0][2] =~ /^menu/i) {
			$Pref{'menuindicator'} = 1; }
		    elsif($_[0][2] =~ /^tab/i) {
			$Pref{'tabindicator'} = 1; }
		    elsif($_[0][2] =~ /^no/i) {
			$Pref{'indicator'} = $Pref{'menuindicator'} = $Pref{'tabindicator'} = 0; }
		    shift @{$_[0]};
		}
		my @str;
		push @str, "fake input" if $Pref{'indicator'};
		push @str, "menu item" if $Pref{'menuindicator'};
		push @str, "tab's label" if $Pref{'tabindicator'};
		push @str, "none" unless scalar @str;
		yell "Active status indicators: ".join', ',@str;
		save_pref;
	}
	elsif(/^start$/) {
		set_self_ident($_[0][2], $_[1][3])  unless $SESS{$network}->{$nick}->{'key_id'};
		if($SESS{$network}->{$nick}->{'key_id'}) {
			if(context_type($partner, $network) == 3) {
				# offering PGP session to a user (type 3)
				command("CTCP $partner PGPLAYER");
			} else {
				yell "Session can be established only with individual users.";
			}

		}
	}
	elsif(/^stop$/) {
		if(uc $_[0][2] eq "FORCE" or scalar @{$SESS{$network}->{$partner}->{'decrypt_buffer'}} == 0) {
			delete $SESS{$network}->{$partner};
			command("NCTCP $partner PGPLAYER 0");
			yell "PGP session closed with $partner";
		} else {
			yell "$partner is transferring something at the moment. Enter /PGP STOP FORCE";
		}
	}
	elsif(/^colou?r$/) {
		$Pref{'PrependChrs'} = $_[1][2];
		save_pref;
	}
	elsif(/^char$/) {
		$Pref{'ModeChr'} = $_[1][2];
		save_pref;
	}
	elsif(/^(no)?debug$/) {
		$Pref{'DEBUG'} = $1 ? 0 : 1;
		save_pref;
	}
	elsif(/^send$/) {
		my $msgtext = $_[1][2];
		unescape \$msgtext;
		my $t_enc;
		my $encrypted = gpg_encrypt ( $msgtext, $SESS{$network}->{$partner}->{'key_id'}, undef, undef, \$t_enc );
		if($encrypted) {
			my @encrypted = partitize ( $encrypted , $Pref{'MAXMSGLEN'} );

			indicator($SESS{$network}->{$partner}->{'receive'}, ++$SESS{$network}->{$partner}->{'transmit'});
			
			$SESS{$network}->{$partner}->{'speaking_base64'} = 1;
			command("SAY $_") for @encrypted;
			$SESS{$network}->{$partner}->{'speaking_base64'} = 0;

			my $Append = $Pref{'DEBUG'} ? sprintf("\cO \cB\cC02[\cO\cC15t_enc=%.2f; slc=%d\cB\cC02]", $t_enc, scalar @encrypted) : '';
			if($msgtext =~ s/^\/me\s+//i) {
				for(split /\n/, $msgtext) {
					emit_print("Your Action", get_info('nick'), $Pref{'PrependChrs'}.$_.$Append, $Pref{'ModeChr'});
					undef $Append;
				}
			} else {
				for(split /\n/, $msgtext) {
					emit_print("Your Message", get_info('nick'), $Pref{'PrependChrs'}.$_.$Append, $Pref{'ModeChr'});
					undef $Append;
				}
			}
		} else {
			yell "Error: GPG mechanism broken. Try to re-enter passphrase by /PGP IDENT"
		}
	}
	else {
		Xchat::print($Help);
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
	my ($channel, $server) = (get_info('channel'), get_info('server'));	# set_context() takes server, not network.
	%server_by_network = map { $_->{'network'} => $_->{'server'} } Xchat::get_list('channels');
	# notify partners
	for $N (keys %SESS) {
		for $P (keys %{$SESS{$N}}) {
			set_context($P, $server_by_network{$N});
			if($SESS{$N}->{$P}->{'key_id'} and not $SESS{$N}->{$P}->{'own'}) {
				command("NCTCP $P PGPLAYER 0");
				yell "PGP session closed with $P";
			}
		}
	}
	set_context($channel, $server);
	Xchat::Internal::unhook($_) for @Hooks;
	return 1;
}


__END__


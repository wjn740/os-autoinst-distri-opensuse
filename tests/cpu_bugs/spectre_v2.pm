# SUSE's openQA tests
#
# Copyright © 2009-2013 Bernhard M. Wiedemann
# Copyright © 2012-2018 SUSE LLC
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.

# Summary: CPU BUGS on Linux kernel check
# Maintainer: James Wang <jnwang@suse.com>

use strict;
use warnings;
#use FindBin;
#use lib $FindBin::Bin;

use base "consoletest";
use bootloader_setup;
use strict;
use testapi;
use utils;
use power_action_utils 'power_action';

use Mitigation;


my %mitigations_list = 
	(
		name => "spectre_v2",
		CPUID => hex '4000000',
		IA32_ARCH_CAPABILITIES => 2, #bit1 -- EIBRS
		parameter => 'spectre_v2',
		cpuflags => ['ibrs', 'ibpb', 'stibp'],
		sysfs => {
				"on" => "Mitigation: Indirect Branch Restricted Speculation.*IBPB: always-on, IBRS_FW, STIBP: forced*", 
				"off" => "Vulnerable,.*IBPB: disabled,.*STIBP: disabled", 
				"auto" => "Mitigation: Indirect Branch Restricted Speculation.*IBPB: conditional, IBRS_FW, STIBP: conditional,*",
				"retpoline" => "Mitigation: Full generic retpoline.*",
				"ibrs" => "Mitigation: Indirect Branch Restricted Speculation.*"
				},
		cmdline => [
				"on",
				"off",
				"auto",
				"retpoline",
				],
	);
sub run {
  my $obj = new Mitigation(\%mitigations_list);
#run base function testing
  $obj->do_test();
}


sub test_flags {
    return { milestone => 1, fatal => 0 };
}

sub post_fail_hook {
    my ($self) = @_;
    select_console 'root-console';
    assert_script_run(
        "md /tmp/upload_mitigations; cp ". $Mitigation::syspath . "* /tmp/upload_mitigations; cp /proc/cmdline /tmp/upload_mitigations; lscpu >/tmp/upload_mitigations/cpuinfo; tar -jcvf /tmp/upload_mitigations.tar.bz2 /tmp/upload_mitigations"
    );
    remove_grub_cmdline_settings('pti=[a-z,]*');
    grub_mkconfig;
    upload_logs '/tmp/upload_mitigations.tar.bz2';
}

1;

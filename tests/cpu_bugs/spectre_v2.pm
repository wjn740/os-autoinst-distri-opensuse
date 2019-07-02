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

my $eibrs_string_on = "Mitigation: Enhanced IBRS, IBPB: always-on, RSB filling";
my $eibrs_string_default = "Mitigation: Enhanced IBRS, IBPB: conditional, RSB filling";
my $retpoline_string = "Mitigation: Full generic retpoline,";

my %mitigations_list = 
	(
		name => "spectre_v2",
		CPUID => hex '4000000',
		IA32_ARCH_CAPABILITIES => 2, #bit1 -- EIBRS
		parameter => 'spectre_v2',
		cpuflags => ['ibrs', 'ibpb', 'stibp'],
    sysfs_name => "spectre_v2",
		sysfs => {
				"on" => "${retpoline_string}.*IBPB: always-on, IBRS_FW, STIBP: forced.*", 
				"off" => "Vulnerable,.*IBPB: disabled,.*STIBP: disabled", 
				"auto" => "${retpoline_string}.*IBPB: conditional, IBRS_FW, STIBP: conditional,.*",
				"retpoline" => "Mitigation: Full generic retpoline.*",
				"default" => "",
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
  my $ret = $obj->vulnerabilities();
    if ($ret == 0) {
	  record_info("EIBRS", "This machine support EIBRS.");
	  $mitigations_list{'sysfs'}->{'on'} = ${eibrs_string_on};
	  $mitigations_list{'sysfs'}->{'auto'} = ${eibrs_string_default};
	  $mitigations_list{'sysfs'}->{'default'} = ${eibrs_string_default};
	  #Fix me.
	  #remove flags make sure testing could continue
	  #EIBRS bit doesn't mean it needn't be tested.
	  $mitigations_list{'IA32_ARCH_CAPABILITIES'} = 0;
    }

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
        "md /tmp/upload_mitigations; cp ". $Mitigation::syspath . "* /tmp/upload_mitigations; cp /proc/cmdline /tmp/upload_mitigations; lscpu >/tmp/upload_mitigations/cpuinfo; journalctl -b >/tmp/upload_mitigations/dmesg.txt; tar -jcvf /tmp/upload_mitigations.tar.bz2 /tmp/upload_mitigations"
    );
    remove_grub_cmdline_settings('spectre_v2=[a-z,]*');
    remove_grub_cmdline_settings('spectre_v2_user=[a-z,]*');
    upload_logs '/tmp/upload_mitigations.tar.bz2';
}

1;

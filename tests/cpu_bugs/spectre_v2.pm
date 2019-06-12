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

my $ibrs_string = "Mitigation: Indirect Branch Restricted Speculation,";
my $retpoline_string = "Mitigation: Full generic retpoline,";
my $spectre_v2_string = $retpoline_string;

my %mitigations_list = 
	(
		name => "spectre_v2",
		CPUID => hex '4000000',
		IA32_ARCH_CAPABILITIES => 2, #bit1 -- EIBRS
		parameter => 'spectre_v2',
		cpuflags => ['ibrs', 'ibpb', 'stibp'],
    sysfs_name => "spectre_v2",
		sysfs => {
				"on" => "${spectre_v2_string}.*IBPB: always-on, IBRS_FW, STIBP: forced.*", 
				"off" => "Vulnerable,.*IBPB: disabled,.*STIBP: disabled", 
				"auto" => "${spectre_v2_string}.*IBPB: conditional, IBRS_FW, STIBP: conditional,.*",
				"retpoline" => "Mitigation: Full generic retpoline.*",
				"ibrs" => "${ibrs_string}"
				},
		cmdline => [
				"on",
				"off",
				"auto",
				"retpoline",
				],
	);
sub run {

    my $cpu_model = script_output(
'cat /proc/cpuinfo | grep "^model[[:blank:]]*\:" | head -1 | awk -F \':\' \'{print $2}\''
    );
    my $cpu_family = script_output(
'cat /proc/cpuinfo | grep "^cpu family[[:blank:]]*\:" | head -1 | awk -F \':\' \'{print $2}\''
    );

        if ( $cpu_family == 6 ) {

            #SkyLake+ processor
            if (   $cpu_model == 0x4E
                or $cpu_model == 0x5E
                or $cpu_model == 0x55
                or $cpu_model == 0x8E
                or $cpu_model == 0x9E )
            {
                record_info( 'SKL+', "Hardware is Intel and SLK+ platform" );
                assert_script_run( "echo cpuinfo->model: " . $cpu_model );
                assert_script_run(
                    'dmesg | grep "Filling RSB on context switch"');
                assert_script_run(
'dmesg | grep "Enabling Restricted Speculation for firmware calls"'
                );
		$mitigations_list{'sysfs'}->{'on'} =~ s/${retpoline_string}/${ibrs_string}/g;
		$mitigations_list{'sysfs'}->{'auto'} =~ s/${retpoline_string}/${ibrs_string}/g;

            }
        }
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
        "md /tmp/upload_mitigations; cp ". $Mitigation::syspath . "* /tmp/upload_mitigations; cp /proc/cmdline /tmp/upload_mitigations; lscpu >/tmp/upload_mitigations/cpuinfo; journalctl -b >/tmp/upload_mitigations/dmesg.txt; tar -jcvf /tmp/upload_mitigations.tar.bz2 /tmp/upload_mitigations"
    );
    remove_grub_cmdline_settings('spectre_v2=[a-z,]*');
    remove_grub_cmdline_settings('spectre_v2_user=[a-z,]*');
    grub_mkconfig;
    upload_logs '/tmp/upload_mitigations.tar.bz2';
}

1;

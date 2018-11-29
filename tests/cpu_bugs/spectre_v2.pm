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

use base "consoletest";
use bootloader_setup;
use strict;
use testapi;
use utils;
use power_action_utils 'power_action';
use Cpuinfo;

sub run {
    my $self = shift;
    my $syspath = '/sys/devices/system/cpu/vulnerabilities/';
    my $cpuinfo = Cpuinfo->new();
    select_console 'root-console';
#check default status
    assert_script_run('cat /proc/cmdline');
    assert_script_run('if ! grep "nospectre_v2" /proc/cmdline; then true; else false; fi');
    assert_script_run('if ! grep "spectre_v2=off" /proc/cmdline; then true; else false; fi');
#check cpu flags.
#Processor platform support these feature, whatever this is a VM or PM.
    assert_script_run('cat /proc/cpuinfo');
    assert_script_run('cat /proc/cpuinfo | grep "^flags.*ibrs.*"');
    assert_script_run('cat /proc/cpuinfo | grep "^flags.*ibpb.*"');
#check sysfs
    assert_script_run('cat ' . $syspath . 'spectre_v2');
    if ( $cpuinfo->cpu_family() == 6) {
#SkyLake+ processor
	if ( $cpuinfo->model() == 0x4E or
             $cpuinfo->model() == 0x5E or
             $cpuinfo->model() == 0x55 or
             $cpuinfo->model() == 0x8E or
             $cpuinfo->model() == 0x9E) {
		assert_script_run('cat ' . $syspath . 'spectre_v2' . '| grep "^Mitigation: Indirect Branch Restricted Speculation.*"');
    		assert_script_run('dmesg | grep "Filling RSB on context switch"');
    		assert_script_run('dmesg | grep "Enabling Indirect Branch Prediction Barrier"');
    		assert_script_run('dmesg | grep "Enabling Restricted Speculation for firmware calls"');
        }
#Older processor
		assert_script_run('cat ' . $syspath . 'spectre_v2' . '| grep "^Mitigation: Full generic retpoline.*"');
#TODO on openSUSE-Leap 42.3 we still need check the following code.
#		assert_script_run('dmesg | grep "Retpolines enabled, force-disabling IBRS due to \!SKL-era core"');
    		assert_script_run('dmesg | grep "Filling RSB on context switch"');
    		assert_script_run('dmesg | grep "Enabling Indirect Branch Prediction Barrier"');
    		assert_script_run('dmesg | grep "Enabling Restricted Speculation for firmware calls"');
    }

#add spectre_v2=off parameter to disable spectre_v2 mitigation
    add_grub_cmdline_settings("spectre_v2=off");
    grub_mkconfig;
#reboot and stand by 
    power_action('reboot', textmode => 1);
    $self->wait_boot(textmode => 1);
    select_console('root-console');

#recheck the status of spectre_v2=off
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "spectre_v2=off" /proc/cmdline');
#check cpu flags
    assert_script_run('cat /proc/cpuinfo');
    assert_script_run('grep "^flags.*ibrs.*" /proc/cpuinfo');
#check sysfs
    assert_script_run('cat ' . $syspath . 'spectre_v2');
    assert_script_run('cat ' . $syspath . 'spectre_v2' . '| grep "^Vulnerable$"');
#chech dmesg
    assert_script_run('if ! dmesg | grep "Spectre V2"; then true; else false; fi');


}

sub test_flags {
    return {milestone => 1, fatal => 0};
}

1;

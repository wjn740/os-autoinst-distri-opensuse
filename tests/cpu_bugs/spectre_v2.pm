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

use cpu_bugs;
use base "consoletest";
use bootloader_setup;
use ipmi_backend_utils;
use power_action_utils 'power_action';
use strict;
use testapi;
use utils;


my $syspath = '/sys/devices/system/cpu/vulnerabilities/';

sub run {
    my $self = shift;
    select_console 'root-console';
#check default status
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep -v "nospectre_v2" /proc/cmdline');
    assert_script_run('grep -v "spectre_v2=off" /proc/cmdline');
#check cpu flags.
#Processor platform support these feature, whatever this is a VM or PM.
    assert_script_run('cat /proc/cpuinfo');
    assert_script_run('lscpu');
    assert_script_run('lscpu | grep "^Flags.*ibrs.*"');
    assert_script_run('lscpu | grep "^Flags.*ibpb.*"');
#check sysfs

    assert_script_run('cat ' . $syspath . 'spectre_v2');

    my $cpu_model = script_output('cat /proc/cpuinfo | grep "^model[[:blank:]]*\:" | head -1 | awk -F \':\' \'{print $2}\'');
    my $cpu_family= script_output('cat /proc/cpuinfo | grep "^cpu family[[:blank:]]*\:" | head -1 | awk -F \':\' \'{print $2}\'');

#
    if ( $cpu_family == 6) {
#SkyLake+ processor
	if ( $cpu_model == 0x4E or
             $cpu_model == 0x5E or
             $cpu_model == 0x55 or
             $cpu_model == 0x8E or
             $cpu_model == 0x9E) {
    		assert_script_run("echo cpuinfo->model: ".$cpu_model);
		assert_script_run('cat ' . $syspath . 'spectre_v2' . '| grep "^Mitigation: Indirect Branch Restricted Speculation.*"');
    		assert_script_run('dmesg | grep "Filling RSB on context switch"');
    		assert_script_run('dmesg | grep "Enabling Indirect Branch Prediction Barrier"');
    		assert_script_run('dmesg | grep "Enabling Restricted Speculation for firmware calls"');
        }else {
#Older processor
    		assert_script_run("echo cpuinfo->model: ".$cpu_model);
		assert_script_run('cat ' . $syspath . 'spectre_v2' . '| grep "^Mitigation: Full generic retpoline.*"');
#TODO on openSUSE-Leap 42.3 we still need check the following code.
#		assert_script_run('dmesg | grep "Retpolines enabled, force-disabling IBRS due to \!SKL-era core"');
    		assert_script_run('dmesg | grep "Filling RSB on context switch"');
    		assert_script_run('dmesg | grep "Enabling Indirect Branch Prediction Barrier"');
    		assert_script_run('dmesg | grep "Enabling Restricted Speculation for firmware calls"');
        }
    }

#add spectre_v2=off parameter to disable spectre_v2 mitigation
    add_grub_cmdline_settings("spectre_v2=off");
    grub_mkconfig;
#reboot and stand by 
    reboot_and_wait(timeout => 70);

#recheck the status of spectre_v2=off
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "spectre_v2=off" /proc/cmdline');
#check cpu flags
    assert_script_run('cat /proc/cpuinfo');
    assert_script_run('grep "^flags.*ibrs.*" /proc/cpuinfo');
    assert_script_run('grep "^flags.*ibpb.*" /proc/cpuinfo');
#check sysfs
    assert_script_run('cat ' . $syspath . 'spectre_v2');
    assert_script_run('cat ' . $syspath . 'spectre_v2' . '| grep "^Vulnerable$"');
#chech dmesg
    assert_script_run('dmesg | grep -v "Spectre V2"');


}

sub test_flags {
    return {milestone => 1, fatal => 0};
}

sub post_fail_hook {
    my ($self) = @_; 
    select_console 'root-console';
    assert_script_run("md /tmp/upload; cp $syspath* /tmp/upload; cp /proc/cmdline /tmp/upload; lscpu >/tmp/upload/cpuinfo; tar -jcvf /tmp/upload.tar.bz2 /tmp/upload");
    remove_grub_cmdline_settings("nospectre_v2");
    remove_grub_cmdline_settings("spectre_v2=.*");
    grub_mkconfig;
    upload_logs '/tmp/upload.tar.bz2';
    $self->SUPER::post_fail_hook;
}

1;

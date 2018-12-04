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
    my $ret = script_run('grep -v "pti=off" /proc/cmdline');
    if ($ret ne 0) {
        remove_grub_cmdline_settings("pti=off");
        grub_mkconfig;
        reboot_and_wait(timeout => 70);
        assert_script_run('grep -v "pti=off" /proc/cmdline');
    }
#che#ck cpu flags
    assert_script_run('cat /proc/cpuinfo');
    assert_script_run('cat /proc/cpuinfo | grep "^flags.*pti.*"');
#che#ck sysfs
    assert_script_run('cat ' . $syspath . 'meltdown');
    assert_script_run('cat ' . $syspath . 'meltdown' . '| grep "^Mitigation: PTI$"');
    assert_script_run('dmesg | grep "Kernel/User page tables isolation: enabled"');

#add pti=off parameter to disable meltdown mitigation
    add_grub_cmdline_settings("pti=off");
    grub_mkconfig;
#reboot and stand by 
    reboot_and_wait(timeout => 70);


#recheck the status of pti=off
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "pti=off" /proc/cmdline');
#check cpu flags
    assert_script_run('cat /proc/cpuinfo');
    assert_script_run('if ! grep "^flags.*pti.*" /proc/cpuinfo; then true; else false; fi');
#check sysfs
    assert_script_run('cat ' . $syspath . 'meltdown');
    assert_script_run('cat ' . $syspath . 'meltdown' . '| grep "^Vulnerable$"');
#chech dmesg
    assert_script_run('dmesg | grep "Kernel/User page tables isolation: disabled on command line."');
    remove_grub_cmdline_settings("pti=off");
    grub_mkconfig;


#add pti=auto parameter to disable meltdown mitigation
    add_grub_cmdline_settings("pti=auto");
    grub_mkconfig;
#reboot and stand by 
    reboot_and_wait(timeout => 70);


#recheck the status of pti=auto
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "pti=auto" /proc/cmdline');
#check cpu flags
    assert_script_run('cat /proc/cpuinfo');
    assert_script_run('if ! grep "^flags.*pti.*" /proc/cpuinfo; then true; else false; fi');
#check sysfs
    assert_script_run('cat ' . $syspath . 'meltdown');
    assert_script_run('cat ' . $syspath . 'meltdown' . '| grep "^Mitigation: PTI$"');
#chech dmesg
    assert_script_run('dmesg | grep "Kernel/User page tables isolation: enabled"');
    remove_grub_cmdline_settings("pti=auto");
    grub_mkconfig;

}

sub test_flags {
    return {milestone => 1, fatal => 0};
}

sub post_fail_hook {
    my ($self) = @_; 
    select_console 'root-console';
    assert_script_run("md /tmp/upload; cp $syspath* /tmp/upload; cp /proc/cmdline /tmp/upload; lscpu >/tmp/upload/cpuinfo; tar -jcvf /tmp/upload.tar.bz2 /tmp/upload");
    remove_grub_cmdline_settings("pti=off");
    remove_grub_cmdline_settings("nopti");
    grub_mkconfig;
    upload_logs '/tmp/upload.tar.bz2';
    $self->SUPER::post_fail_hook;
}

1;

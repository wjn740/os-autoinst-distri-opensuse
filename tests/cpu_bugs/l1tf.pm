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
    assert_script_run('if ! grep "l1tf=off" /proc/cmdline; then true; else false; fi');
#check cpu flags.
#Processor platform support these feature, whatever this is a VM or PM.
    assert_script_run('cat /proc/cpuinfo');
    my $ret = script_run('cat /proc/cpuinfo | grep "^flags.*vmx.*"');
    if ($ret ne 0) {
	record_soft_failure("This machine doesn't support VMX feature.");
    	assert_script_run('cat ' . $syspath . 'l1tf' . '| grep "^Mitigation: PTE Inversion$"');
	return;
    }

#check CPU status
    assert_script_run('lscpu');
#check sysfs
    assert_script_run('cat ' . $syspath . 'l1tf');
    assert_script_run('cat ' . $syspath . 'l1tf' . '| grep "^Mitigation: PTE Inversion; VMX: conditional cache flushes, SMT vulnerable$"');

#########
# Sub case 1: l1tf=off
#########
#add l1tf=off parameter to disable ssbd mitigation
    add_grub_cmdline_settings("l1tf=off");
    grub_mkconfig;
#reboot and stand by 
    power_action('reboot', textmode => 1);
    $self->wait_boot(textmode => 1);
    select_console('root-console');

#recheck the status of l1tf=off
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "l1tf=off" /proc/cmdline');
#check sysfs
    assert_script_run('cat ' . $syspath . 'l1tf');
    assert_script_run('cat ' . $syspath . 'l1tf' . '| grep "^Mitigation: PTE Inversion; VMX: vulnerable$"');
#chech dmesg
    remove_grub_cmdline_settings("l1tf=off");



#########
# Sub case 2: l1tf=full
#########
#add spec_store_bypass_disable=full parameter to disable ssbd mitigation
    add_grub_cmdline_settings("l1tf=full");
    grub_mkconfig;
#reboot and stand by 
    power_action('reboot', textmode => 1);
    $self->wait_boot(textmode => 1);
    select_console('root-console');

#recheck the status of spec_store_bypass_disable=full
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "l1tf=full" /proc/cmdline');
#check sysfs
    assert_script_run('cat ' . $syspath . 'l1tf');
    assert_script_run('cat ' . $syspath . 'l1tf' . '| grep "^Mitigation: PTE Inversion; VMX: cache flushes, SMT disabled$"');
    remove_grub_cmdline_settings("l1tf=full");


#########
# Sub case 3: l1tf=full,force
#########
#add l1tf=full,force parameter to disable ssbd mitigation
    add_grub_cmdline_settings("l1tf=full,force");
    grub_mkconfig;
#reboot and stand by 
    power_action('reboot', textmode => 1);
    $self->wait_boot(textmode => 1);
    select_console('root-console');

#recheck the status of l1tf=full,force
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "l1tf=full,force" /proc/cmdline');
#check cpu flags
    assert_script_run('cat /proc/cpuinfo');
#check sysfs
    assert_script_run('cat ' . $syspath . 'l1tf');
    assert_script_run('cat ' . $syspath . 'l1tf' . '| grep "^Mitigation: PTE Inversion; VMX: cache flushes, SMT disabled$"');



#remove parameter
    remove_grub_cmdline_settings("l1tf=full,force");


#########
# Sub case 4: l1tf=flush,nosmt
#########
#add l1tf=flush,nosmt parameter to disable ssbd mitigation
    add_grub_cmdline_settings("l1tf=flush,nosmt");
    grub_mkconfig;
#reboot and stand by 
    power_action('reboot', textmode => 1);
    $self->wait_boot(textmode => 1);
    select_console('root-console');

#recheck the status of l1tf=flush,nosmt
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "l1tf=flush,nosmt" /proc/cmdline');
#check cpu flags
    assert_script_run('cat /proc/cpuinfo');
#check sysfs
    assert_script_run('cat ' . $syspath . 'l1tf');
    assert_script_run('cat ' . $syspath . 'l1tf' . '| grep "^Mitigation: PTE Inversion; VMX: conditional cache flushes, SMT disabled$"');
    remove_grub_cmdline_settings("l1tf=flush,nosmt");

#########
# Sub case 5: l1tf=flush,nowarn
#########
#add l1tf=flush,nowarn parameter to trigger a exception
    add_grub_cmdline_settings("l1tf=flush,nowarn");
    grub_mkconfig;
#reboot and stand by 
    power_action('reboot', textmode => 1);
    $self->wait_boot(textmode => 1);
    select_console('root-console');

#recheck the status of l1tf=flush,nowarn
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "l1tf=flush,nowarn" /proc/cmdline');
#check cpu flags
    assert_script_run('cat /proc/cpuinfo');
#check sysfs
    assert_script_run('cat ' . $syspath . 'l1tf');
    assert_script_run('cat ' . $syspath . 'l1tf' . '| grep "^Mitigation: PTE Inversion; VMX: conditional cache flushes, SMT vulnerable$"');
    remove_grub_cmdline_settings("l1tf=flush,nowarn");
}

sub test_flags {
    return {milestone => 1, fatal => 0};
}

1;

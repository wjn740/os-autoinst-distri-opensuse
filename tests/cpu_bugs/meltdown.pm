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

sub run {
    my $self = shift;
    my $syspath = '/sys/devices/system/cpu/vulnerabilities/';
    select_console 'root-console';
#check default status
    assert_script_run('cat /proc/cmdline');
    assert_script_run('if ! grep "pti=off" /proc/cpuinfo; then true; else false; fi');
#check cpu flags
    assert_script_run('cat /proc/cpuinfo');
    assert_script_run('cat /proc/cpuinfo | grep "^flags.*pti.*"');
#check sysfs
    assert_script_run('cat ' . $syspath . 'meltdown');
    assert_script_run('cat ' . $syspath . 'meltdown' . '| grep "^Mitigation: PTI$"');
    assert_script_run('dmesg | grep "Kernel/User page tables isolation: enabled"');

#add pti=off parameter to disable meltdown mitigation
    add_grub_cmdline_settings("pti=off");
    grub_mkconfig;
#reboot and stand by 
    power_action('reboot', textmode => 1);
    $self->wait_boot(textmode => 1);
    select_console('root-console');

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


}

sub test_flags {
    return {milestone => 1, fatal => 0};
}

1;

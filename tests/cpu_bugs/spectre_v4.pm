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
    assert_script_run('if ! grep "nospec_store_bypass_disable" /proc/cmdline; then true; else false; fi');
    assert_script_run('if ! grep "spec_store_bypass_disable=off" /proc/cmdline; then true; else false; fi');
#check cpu flags
    assert_script_run('cat /proc/cpuinfo');
    assert_script_run('cat /proc/cpuinfo | grep "^flags.*ssbd.*"');
#check sysfs
    assert_script_run('cat ' . $syspath . 'spec_store_bypass');
    assert_script_run('cat ' . $syspath . 'spec_store_bypass' . '| grep "^Mitigation: Speculative Store Bypass disabled via prctl and seccomp$"');
    assert_script_run('dmesg | grep "Speculative Store Bypass: Mitigation: Speculative Store Bypass disabled via prctl and seccomp"');

#########
# Sub case 1: spec_store_bypass_disable=off
#########
#add spec_store_bypass_disable=off parameter to disable ssbd mitigation
    add_grub_cmdline_settings("spec_store_bypass_disable=off");
    grub_mkconfig;
#reboot and stand by 
    power_action('reboot', textmode => 1);
    $self->wait_boot(textmode => 1);
    select_console('root-console');

#recheck the status of spec_store_bypass_disable=off
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "spec_store_bypass_disable=off" /proc/cmdline');
#check sysfs
    assert_script_run('cat ' . $syspath . 'spec_store_bypass');
    assert_script_run('cat ' . $syspath . 'spec_store_bypass' . '| grep "^Vulnerable$"');
#chech dmesg
    assert_script_run('dmesg | grep "Speculative Store Bypass: Vulnerable"');
    remove_grub_cmdline_settings("spec_store_bypass_disable=off");



#########
# Sub case 2: spec_store_bypass_disable=auto
#########
#add spec_store_bypass_disable=auto parameter to disable ssbd mitigation
    add_grub_cmdline_settings("spec_store_bypass_disable=auto");
    grub_mkconfig;
#reboot and stand by 
    power_action('reboot', textmode => 1);
    $self->wait_boot(textmode => 1);
    select_console('root-console');

#recheck the status of spec_store_bypass_disable=auto
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "spec_store_bypass_disable=auto" /proc/cmdline');
#check cpu flags
    assert_script_run('cat /proc/cpuinfo');
#check sysfs
    assert_script_run('cat ' . $syspath . 'spec_store_bypass');
#TODO
#The context depends on CONFIG_SECCOMP of kernel. If it is Y, then
    assert_script_run('cat ' . $syspath . 'spec_store_bypass' . '| grep "^Mitigation: Speculative Store Bypass disabled via prctl and seccomp$"');
#chech dmesg
    assert_script_run('dmesg | grep "Speculative Store Bypass: Mitigation: Speculative Store Bypass disabled via prctl and seccomp"');
#otherwise, the output should be:
#    assert_script_run('cat ' . $syspath . 'spec_store_bypass' . '| grep "^Mitigation: Speculative Store Bypass disabled via prctl$"');
#    assert_script_run('dmesg | grep "Speculative Store Bypass: Mitigation: Speculative Store Bypass disabled via prctl"');
    remove_grub_cmdline_settings("spec_store_bypass_disable=auto");


#########
# Sub case 3: spec_store_bypass_disable=prctl
#########
#add spec_store_bypass_disable=prctl parameter to disable ssbd mitigation
    add_grub_cmdline_settings("spec_store_bypass_disable=prctl");
    grub_mkconfig;
#reboot and stand by 
    power_action('reboot', textmode => 1);
    $self->wait_boot(textmode => 1);
    select_console('root-console');

#recheck the status of spec_store_bypass_disable=prctl
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "spec_store_bypass_disable=prctl" /proc/cmdline');
#check cpu flags
    assert_script_run('cat /proc/cpuinfo');
#check sysfs
    assert_script_run('cat ' . $syspath . 'spec_store_bypass');
    assert_script_run('cat ' . $syspath . 'spec_store_bypass' . '| grep "^Mitigation: Speculative Store Bypass disabled via prctl$"');
#chech dmesg
    assert_script_run('dmesg | grep "Speculative Store Bypass: Mitigation: Speculative Store Bypass disabled via prctl"');
    remove_grub_cmdline_settings("spec_store_bypass_disable=prctl");


#########
# Sub case 4: spec_store_bypass_disable=seccomp
#########
#add spec_store_bypass_disable=seccomp parameter to disable ssbd mitigation
    add_grub_cmdline_settings("spec_store_bypass_disable=seccomp");
    grub_mkconfig;
#reboot and stand by 
    power_action('reboot', textmode => 1);
    $self->wait_boot(textmode => 1);
    select_console('root-console');

#recheck the status of spec_store_bypass_disable=seccomp
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "spec_store_bypass_disable=seccomp" /proc/cmdline');
#check cpu flags
    assert_script_run('cat /proc/cpuinfo');
#check sysfs
    assert_script_run('cat ' . $syspath . 'spec_store_bypass');
    assert_script_run('cat ' . $syspath . 'spec_store_bypass' . '| grep "^Mitigation: Speculative Store Bypass disabled via prctl and seccomp$"');
#chech dmesg
    assert_script_run('dmesg | grep "Speculative Store Bypass: Mitigation: Speculative Store Bypass disabled via prctl and seccomp"');
    remove_grub_cmdline_settings("spec_store_bypass_disable=seccomp");

#########
# Sub case 5: spec_store_bypass_disable=test
#########
#add spec_store_bypass_disable=test parameter to trigger a exception
    add_grub_cmdline_settings("spec_store_bypass_disable=test");
    grub_mkconfig;
#reboot and stand by 
    power_action('reboot', textmode => 1);
    $self->wait_boot(textmode => 1);
    select_console('root-console');

#recheck the status of spec_store_bypass_disable=test
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "spec_store_bypass_disable=test" /proc/cmdline');
#check cpu flags
    assert_script_run('cat /proc/cpuinfo');
#check sysfs
    assert_script_run('cat ' . $syspath . 'spec_store_bypass');
    assert_script_run('cat ' . $syspath . 'spec_store_bypass' . '| grep "^Mitigation: Speculative Store Bypass disabled via prctl and seccomp$"');
#chech dmesg
    assert_script_run('dmesg | grep "Speculative Store Bypass: Mitigation: Speculative Store Bypass disabled via prctl and seccomp"');
    assert_script_run('dmesg | grep "Speculative Store Bypass: Mitigation: Speculative Store Bypass disabled via prctl and seccomp"');
    remove_grub_cmdline_settings("spec_store_bypass_disable=test");
}

sub test_flags {
    return {milestone => 1, fatal => 0};
}

1;

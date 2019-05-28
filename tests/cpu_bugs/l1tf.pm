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
use cpu_bugs;

my $syspath = '/sys/devices/system/cpu/vulnerabilities/';

sub run {
    my $self = shift;
    my $smt  = undef;
    select_console 'root-console';

    #check microcode is updated
    if ( check_var( 'BACKEND', 'ipmi' ) ) {
        zypper_call("in cpuid");
        my $edx = script_output(
"cpuid -1 -l 7 -s 0 -r | awk \'{print \$6}\' | awk -F \"=\" \'{print \$2}\' | tail -n1"
        );
        if ( hex $edx & 0x10000000 ) {
            assert_script_run(
"(echo \"Ucode has been update for L1D flush support\") | tee /dev/$serialdev"
            );
            record_info( 'ok', "Hardware support L1D_flush" );
        }
        else {
            record_info( 'fail', "Hardware doesn't support L1D_flush" );
            die "Hardware doesn't support L1D_flush";
        }
    }
    elsif ( get_var( 'BACKEND', 'qemu' ) ) {
        record_info( 'softfail', "QEMU needn't run this testcase" );
        return;
    }

    #check default status
    assert_script_run('cat /proc/cmdline');
    my $ret = script_run('grep -v "l1tf=.*" /proc/cmdline');
    if ( $ret ne 0 ) {
        remove_grub_cmdline_settings("l1tf=[a-z,]*");
        grub_mkconfig;
        reboot_and_wait( $self, 150 );
    }

    #check cpu flags.
    #Processor platform support these feature, whatever this is a VM or PM.
    $ret = script_run('cat /proc/cpuinfo | grep "^flags.*vmx.*"');
    if ( $ret ne 0 ) {
        record_soft_failure("This machine doesn't support VMX feature.");
        assert_script_run( 'cat '
              . $syspath . 'l1tf'
              . '| grep "^Mitigation: PTE Inversion$"' );
        return;
    }

    #check CPU status
    assert_script_run('lscpu');

    #check sysfs
    assert_script_run( 'cat ' . $syspath . 'l1tf' );
    assert_script_run( 'cat '
          . $syspath . 'l1tf'
          . '| grep "^Mitigation: PTE Inversion; VMX: conditional cache flushes, SMT vulnerable$"'
    );
    assert_script_run(
        "cat /sys/module/kvm_intel/parameters/vmentry_l1d_flush | grep \"cond\""
    );
    assert_script_run(
        "echo \"never\" > /sys/module/kvm_intel/parameters/vmentry_l1d_flush");
    assert_script_run(
"cat /sys/module/kvm_intel/parameters/vmentry_l1d_flush | grep \"never\""
    );
    $smt = script_output("cat /sys/devices/system/cpu/smt/control");
    if ( $smt != "notsupported" ) {
        assert_script_run(
            "cat /sys/devices/system/cpu/smt/control | grep \"on\"");
    }

#########
    # Sub case 1: l1tf=off
#########
    #add l1tf=off parameter to disable ssbd mitigation
    add_grub_cmdline_settings("l1tf=off");
    grub_mkconfig;

    #reboot and stand by
    reboot_and_wait( $self, 150 );

    #recheck the status of l1tf=off
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "l1tf=off" /proc/cmdline');

    #check sysfs
    assert_script_run( 'cat ' . $syspath . 'l1tf' );
    assert_script_run( 'cat '
          . $syspath . 'l1tf'
          . '| grep "^Mitigation: PTE Inversion; VMX: vulnerable$"' );

    assert_script_run(
"cat /sys/module/kvm_intel/parameters/vmentry_l1d_flush | grep \"never\""
    );
    assert_script_run(
        "echo \"cond\" > /sys/module/kvm_intel/parameters/vmentry_l1d_flush");
    assert_script_run(
        "cat /sys/module/kvm_intel/parameters/vmentry_l1d_flush | grep \"cond\""
    );
    $smt = script_output("cat /sys/devices/system/cpu/smt/control");
    if ( $smt != "notsupported" ) {
        assert_script_run(
            "cat /sys/devices/system/cpu/smt/control | grep \"on\"");
    }

    #remove parameter
    remove_grub_cmdline_settings("l1tf=off");

#########
    # Sub case 2: l1tf=full
#########
    #add spec_store_bypass_disable=full parameter to disable ssbd mitigation
    add_grub_cmdline_settings("l1tf=full");
    grub_mkconfig;

    #reboot and stand by
    reboot_and_wait( $self, 150 );

    #recheck the status of spec_store_bypass_disable=full
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "l1tf=full" /proc/cmdline');

    #check sysfs
    assert_script_run( 'cat ' . $syspath . 'l1tf' );
    assert_script_run( 'cat '
          . $syspath . 'l1tf'
          . '| grep "^Mitigation: PTE Inversion; VMX: cache flushes, SMT disabled$"'
    );

    assert_script_run(
"cat /sys/module/kvm_intel/parameters/vmentry_l1d_flush | grep \"always\""
    );
    assert_script_run(
        "echo \"cond\" > /sys/module/kvm_intel/parameters/vmentry_l1d_flush");
    assert_script_run(
        "cat /sys/module/kvm_intel/parameters/vmentry_l1d_flush | grep \"cond\""
    );
    $smt = script_output("cat /sys/devices/system/cpu/smt/control");
    if ( $smt != "notsupported" ) {
        assert_script_run(
            "cat /sys/devices/system/cpu/smt/control | grep \"off\"");
    }

    remove_grub_cmdline_settings("l1tf=full");

#########
    # Sub case 3: l1tf=full,force
#########
    #add l1tf=full,force parameter to disable ssbd mitigation
    add_grub_cmdline_settings("l1tf=full,force");
    grub_mkconfig;

    #reboot and stand by
    reboot_and_wait( $self, 150 );

    #recheck the status of l1tf=full,force
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "l1tf=full,force" /proc/cmdline');

    #check cpu flags
    assert_script_run('cat /proc/cpuinfo');

    #check sysfs
    assert_script_run( 'cat ' . $syspath . 'l1tf' );
    assert_script_run( 'cat '
          . $syspath . 'l1tf'
          . '| grep "^Mitigation: PTE Inversion; VMX: cache flushes, SMT disabled$"'
    );

    assert_script_run(
"cat /sys/module/kvm_intel/parameters/vmentry_l1d_flush | grep \"always\""
    );
    assert_script_run(
        "echo \"cond\" > /sys/module/kvm_intel/parameters/vmentry_l1d_flush");
    assert_script_run(
"cat /sys/module/kvm_intel/parameters/vmentry_l1d_flush | tee \"always\""
    );
    $smt = script_output("cat /sys/devices/system/cpu/smt/control");
    if ( $smt != "notsupported" ) {
        assert_script_run(
            "cat /sys/devices/system/cpu/smt/control | grep \"forceoff\"");
        wait_serial("forceoff");
    }

    #remove parameter
    remove_grub_cmdline_settings("l1tf=full,force");

#########
    # Sub case 4: l1tf=flush,nosmt
#########
    #add l1tf=flush,nosmt parameter to disable ssbd mitigation
    add_grub_cmdline_settings("l1tf=flush,nosmt");
    grub_mkconfig;

    #reboot and stand by
    reboot_and_wait( $self, 150 );

    #recheck the status of l1tf=flush,nosmt
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "l1tf=flush,nosmt" /proc/cmdline');

    #check cpu flags
    assert_script_run('cat /proc/cpuinfo');

    #check sysfs
    assert_script_run( 'cat ' . $syspath . 'l1tf' );
    assert_script_run( 'cat '
          . $syspath . 'l1tf'
          . '| grep "^Mitigation: PTE Inversion; VMX: conditional cache flushes, SMT disabled$"'
    );

    assert_script_run(
        "cat /sys/module/kvm_intel/parameters/vmentry_l1d_flush | grep \"cond\""
    );
    assert_script_run(
        "echo \"always\" > /sys/module/kvm_intel/parameters/vmentry_l1d_flush");
    assert_script_run(
"cat /sys/module/kvm_intel/parameters/vmentry_l1d_flush | grep \"always\""
    );
    $smt = script_output("cat /sys/devices/system/cpu/smt/control");
    if ( $smt != "notsupported" ) {
        assert_script_run(
            "cat /sys/devices/system/cpu/smt/control | grep \"off\"");
    }

    remove_grub_cmdline_settings("l1tf=flush,nosmt");

#########
    # Sub case 5: l1tf=flush,nowarn
#########
    #add l1tf=flush,nowarn parameter to trigger a exception
    add_grub_cmdline_settings("l1tf=flush,nowarn");
    grub_mkconfig;

    #reboot and stand by
    reboot_and_wait( $self, 150 );

    #recheck the status of l1tf=flush,nowarn
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "l1tf=flush,nowarn" /proc/cmdline');

    #check cpu flags
    assert_script_run('cat /proc/cpuinfo');

    #check sysfs
    assert_script_run( 'cat ' . $syspath . 'l1tf' );
    assert_script_run( 'cat '
          . $syspath . 'l1tf'
          . '| grep "^Mitigation: PTE Inversion; VMX: conditional cache flushes, SMT vulnerable$"'
    );

    assert_script_run(
        "cat /sys/module/kvm_intel/parameters/vmentry_l1d_flush | grep \"cond\""
    );
    assert_script_run(
        "echo \"never\" > /sys/module/kvm_intel/parameters/vmentry_l1d_flush");
    assert_script_run(
"cat /sys/module/kvm_intel/parameters/vmentry_l1d_flush | grep \"never\""
    );
    $smt = script_output("cat /sys/devices/system/cpu/smt/control");
    if ( $smt != "notsupported" ) {
        assert_script_run(
            "cat /sys/devices/system/cpu/smt/control | grep \"on\"");
    }
    remove_grub_cmdline_settings("l1tf=flush,nowarn");

#########
    # Sub case 6: l1tf=test
#########
    #add l1tf=flush,nowarn parameter to trigger a exception
    add_grub_cmdline_settings("l1tf=test");
    grub_mkconfig;

    #reboot and stand by
    reboot_and_wait( $self, 150 );

    #recheck the status of l1tf=test
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "l1tf=test" /proc/cmdline');

    #check cpu flags
    assert_script_run('cat /proc/cpuinfo');

    #check sysfs
    assert_script_run( 'cat ' . $syspath . 'l1tf' );
    assert_script_run( 'cat '
          . $syspath . 'l1tf'
          . '| grep "^Mitigation: PTE Inversion; VMX: conditional cache flushes, SMT vulnerable$"'
    );
    remove_grub_cmdline_settings("l1tf=test");

#########
    # Sub case 7: EPT is 0
#########
    #add l1tf=flush,nowarn parameter to trigger a exception
    add_grub_cmdline_settings("kvm-intel.ept=0");
    grub_mkconfig;

    #reboot and stand by
    reboot_and_wait( $self, 150 );

    #check sysfs
    assert_script_run('cat /sys/module/kvm_intel/parameters/ept | grep "^N$"');
    remove_grub_cmdline_settings("kvm-intel.ept=0");
}

sub test_flags {
    return { milestone => 1, fatal => 0 };
}

sub post_fail_hook {
    my ($self) = @_;
    select_console 'root-console';
    assert_script_run(
"md /tmp/upload; cp $syspath* /tmp/upload; cp /proc/cmdline /tmp/upload; lscpu >/tmp/upload/cpuinfo; tar -jcvf /tmp/upload.tar.bz2 /tmp/upload"
    );
    remove_grub_cmdline_settings('l1tf=[a-z,]*');
    grub_mkconfig;
    upload_logs '/tmp/upload.tar.bz2';
    $self->SUPER::post_fail_hook;
}

1;

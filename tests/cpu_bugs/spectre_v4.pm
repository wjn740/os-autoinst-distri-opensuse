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
    my $supported;
    select_console 'root-console';

    zypper_call("in cpuid");
    my $edx = script_output(
"cpuid -1 -l 7 -s 0 -r | awk \'{print \$6}\' | awk -F \"=\" \'{print \$2}\' | tail -n1"
    );
    if ( hex $edx & 0x80000000 ) {
        assert_script_run(
"(echo \"Ucode has been update for SSBD support\") | tee /dev/$serialdev"
        );
        record_info( 'ok', "Hardware support SSBD" );
        $supported = 1;
    }
    else {
        record_info( 'fail', "Hardware doesn't support SSBD" );
        $supported = 0;
    }

    if ($supported) {

        #check default status
        assert_script_run('cat /proc/cmdline');
        my $ret1 =
          script_run('grep -v "nospec_store_bypass_disable" /proc/cmdline');
        my $ret2 =
          script_run('grep -v "spec_store_bypass_disable=off" /proc/cmdline');
        if ( $ret1 ne 0 or $ret2 ne 0 ) {
            remove_grub_cmdline_settings("nospec_store_bypass_disable");
            remove_grub_cmdline_settings("spec_store_bypass_disable=[a-z,]*");
            grub_mkconfig;
            reboot_and_wait( $self, 150 );
        }

        #check cpu flags
        assert_script_run('cat /proc/cpuinfo');
        assert_script_run('cat /proc/cpuinfo | grep "^flags.*ssbd.*"');
        assert_script_run('lscpu | grep "^Flags.*ssbd.*"');

        #check sysfs
        assert_script_run( 'cat ' . $syspath . 'spec_store_bypass' );
        assert_script_run( 'cat '
              . $syspath
              . 'spec_store_bypass'
              . '| grep "^Mitigation: Speculative Store Bypass disabled via prctl and seccomp$"'
        );
        assert_script_run(
'dmesg | grep "Speculative Store Bypass: Mitigation: Speculative Store Bypass disabled via prctl and seccomp"'
        );

#########
        # Sub case 1: spec_store_bypass_disable=off
#########
        #add spec_store_bypass_disable=off parameter to disable ssbd mitigation
        add_grub_cmdline_settings("spec_store_bypass_disable=off");
        grub_mkconfig;

        #reboot and stand by
        reboot_and_wait( $self, 150 );

        #recheck the status of spec_store_bypass_disable=off
        assert_script_run('cat /proc/cmdline');
        assert_script_run('grep "spec_store_bypass_disable=off" /proc/cmdline');

        #check sysfs
        assert_script_run( 'cat ' . $syspath . 'spec_store_bypass' );
        assert_script_run(
            'cat ' . $syspath . 'spec_store_bypass' . '| grep "^Vulnerable$"' );

        #chech dmesg
        assert_script_run(
            'dmesg | grep "Speculative Store Bypass: Vulnerable"');
        remove_grub_cmdline_settings("spec_store_bypass_disable=off");

#########
        # Sub case 2: spec_store_bypass_disable=auto
#########
        #add spec_store_bypass_disable=auto parameter to disable ssbd mitigation
        add_grub_cmdline_settings("spec_store_bypass_disable=auto");
        grub_mkconfig;

        #reboot and stand by
        reboot_and_wait( $self, 150 );

        #recheck the status of spec_store_bypass_disable=auto
        assert_script_run('cat /proc/cmdline');
        assert_script_run(
            'grep "spec_store_bypass_disable=auto" /proc/cmdline');

        #check cpu flags
        assert_script_run('cat /proc/cpuinfo');

        #check sysfs
        assert_script_run( 'cat ' . $syspath . 'spec_store_bypass' );

        #TODO
        #The context depends on CONFIG_SECCOMP of kernel. If it is Y, then
        assert_script_run( 'cat '
              . $syspath
              . 'spec_store_bypass'
              . '| grep "^Mitigation: Speculative Store Bypass disabled via prctl and seccomp$"'
        );

        #chech dmesg
        assert_script_run(
'dmesg | grep "Speculative Store Bypass: Mitigation: Speculative Store Bypass disabled via prctl and seccomp"'
        );

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
        reboot_and_wait( $self, 150 );

        #recheck the status of spec_store_bypass_disable=prctl
        assert_script_run('cat /proc/cmdline');
        assert_script_run(
            'grep "spec_store_bypass_disable=prctl" /proc/cmdline');

        #check cpu flags
        assert_script_run('cat /proc/cpuinfo');

        #check sysfs
        assert_script_run( 'cat ' . $syspath . 'spec_store_bypass' );
        assert_script_run( 'cat '
              . $syspath
              . 'spec_store_bypass'
              . '| grep "^Mitigation: Speculative Store Bypass disabled via prctl$"'
        );

        #chech dmesg
        assert_script_run(
'dmesg | grep "Speculative Store Bypass: Mitigation: Speculative Store Bypass disabled via prctl"'
        );
        remove_grub_cmdline_settings("spec_store_bypass_disable=prctl");

#########
        # Sub case 4: spec_store_bypass_disable=seccomp
#########
     #add spec_store_bypass_disable=seccomp parameter to disable ssbd mitigation
        add_grub_cmdline_settings("spec_store_bypass_disable=seccomp");
        grub_mkconfig;

        #reboot and stand by
        reboot_and_wait( $self, 150 );

        #recheck the status of spec_store_bypass_disable=seccomp
        assert_script_run('cat /proc/cmdline');
        assert_script_run(
            'grep "spec_store_bypass_disable=seccomp" /proc/cmdline');

        #check cpu flags
        assert_script_run('cat /proc/cpuinfo');

        #check sysfs
        assert_script_run( 'cat ' . $syspath . 'spec_store_bypass' );
        assert_script_run( 'cat '
              . $syspath
              . 'spec_store_bypass'
              . '| grep "^Mitigation: Speculative Store Bypass disabled via prctl and seccomp$"'
        );

        #chech dmesg
        assert_script_run(
'dmesg | grep "Speculative Store Bypass: Mitigation: Speculative Store Bypass disabled via prctl and seccomp"'
        );
        remove_grub_cmdline_settings("spec_store_bypass_disable=seccomp");

#########
        # Sub case 5: spec_store_bypass_disable=test
#########
        #add spec_store_bypass_disable=test parameter to trigger a exception
        add_grub_cmdline_settings("spec_store_bypass_disable=test");
        grub_mkconfig;

        #reboot and stand by
        reboot_and_wait( $self, 150 );

        #recheck the status of spec_store_bypass_disable=test
        assert_script_run('cat /proc/cmdline');
        assert_script_run(
            'grep "spec_store_bypass_disable=test" /proc/cmdline');

        #check cpu flags
        assert_script_run('cat /proc/cpuinfo');

        #check sysfs
        assert_script_run( 'cat ' . $syspath . 'spec_store_bypass' );
        assert_script_run( 'cat '
              . $syspath
              . 'spec_store_bypass'
              . '| grep "^Mitigation: Speculative Store Bypass disabled via prctl and seccomp$"'
        );

        #chech dmesg
        assert_script_run(
'dmesg | grep "Speculative Store Bypass: Mitigation: Speculative Store Bypass disabled via prctl and seccomp"'
        );
        assert_script_run(
'dmesg | grep "Speculative Store Bypass: Mitigation: Speculative Store Bypass disabled via prctl and seccomp"'
        );
        remove_grub_cmdline_settings("spec_store_bypass_disable=test");
    }
    elsif ( $supported eq 0 ) {

        #chech dmesg
        assert_script_run(
'dmesg | grep -v "Speculative Store Bypass: Mitigation: Speculative Store Bypass disabled via prctl and seccomp"'
        );
        assert_script_run(
            'dmesg | grep -v "Speculative Store Bypass: Mitigation: .*"');
    }
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
    remove_grub_cmdline_settings('spec_store_bypass_disable=[a-z,]*');
    remove_grub_cmdline_settings('nospec_store_bypass_disable');
    grub_mkconfig;
    upload_logs '/tmp/upload.tar.bz2';
    $self->SUPER::post_fail_hook;
}

1;

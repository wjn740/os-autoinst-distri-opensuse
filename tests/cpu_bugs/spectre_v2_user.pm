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

    zypper_call("in cpuid");
    my $edx = script_output(
"cpuid -1 -l 7 -s 0 -r | awk \'{print \$6}\' | awk -F \"=\" \'{print \$2}\' | tail -n1"
    );
    if ( hex $edx & 0x0C000000 ) {
        assert_script_run(
"(echo \"Ucode has been update for STIBP and IBPB support\") | tee /dev/$serialdev"
        );
        record_info( 'ok', "Hardware support STIBP and IBPB" );
    }
    else {
        record_info( 'softfail', "Hardware doesn't support STIBP and IBPB" );
	return;
    }
    my $cpu_model = script_output(
'cat /proc/cpuinfo | grep "^model[[:blank:]]*\:" | head -1 | awk -F \':\' \'{print $2}\''
    );
    my $cpu_family = script_output(
'cat /proc/cpuinfo | grep "^cpu family[[:blank:]]*\:" | head -1 | awk -F \':\' \'{print $2}\''
    );

        #check default status
        assert_script_run('cat /proc/cmdline');
        my $ret1 = script_run('grep -v "nospectre_v2" /proc/cmdline');
        my $ret2 = script_run('grep -v "spectre_v2=[a-z,]*" /proc/cmdline');
        my $ret3 = script_run('grep -v "spectre_v2_user=[a-z,]*" /proc/cmdline');
        my $ret4 = script_run('grep -v "mitigations=off" /proc/cmdline');
        if ( $ret1 ne 0 or $ret2 ne 0  or $ret3 ne 0 or $ret4 ne 0) {
            remove_grub_cmdline_settings("nospectre_v2");
            remove_grub_cmdline_settings("spectre_v2=[a-z,]*");
            remove_grub_cmdline_settings("spectre_v2_user=[a-z,]*");
            remove_grub_cmdline_settings("mitigations=off");
            grub_mkconfig;
            reboot_and_wait( $self, 150 );
            assert_script_run('grep -v "nospectre_v2" /proc/cmdline');
            assert_script_run('grep -v "spectre_v2=off" /proc/cmdline');
            assert_script_run('grep -v "spectre_v2_user=off" /proc/cmdline');
        }

        #check cpu flags.
        #Processor platform support these feature, whatever this is a VM or PM.
        assert_script_run('cat /proc/cpuinfo');
        assert_script_run('lscpu');
        assert_script_run('lscpu | grep "^Flags.*ibpb.*"');
        assert_script_run('lscpu | grep "^Flags.*stibp.*"');

        #check sysfs

        assert_script_run( 'cat ' . $syspath . 'spectre_v2' );

        #
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
                assert_script_run( 'cat '
                      . $syspath
                      . 'spectre_v2'
                      . '| grep "^Mitigation: Indirect Branch Restricted Speculation.* IBPB: conditional,.* STIBP: conditional,.*"'
                );
            }
            else {
                #Older processor
                record_info( '!SKL+', "Hardware is Intel and !SLK+ platforms" );
                assert_script_run( "echo cpuinfo->model: " . $cpu_model );
                assert_script_run( 'cat '
                      . $syspath
                      . 'spectre_v2'
                      . '| grep "^Mitigation: Indirect Branch Restricted Speculation.* IBPB: conditional,.* STIBP: conditional,.*"'
                );
            }
        }

        record_info( 'suppported STIBP and IBPB mode',
            "spectre_v2_user default mode finish." );

        #add spectre_v2_user=auto parameter to disable spectre_v2 mitigation
        add_grub_cmdline_settings("spectre_v2_user=auto");
        grub_mkconfig;

        #reboot and stand by
        reboot_and_wait( $self, 150 );
        record_info( 'auto mode start', "spectre_v2_user=auto start." );

        #recheck the status of spectre_v2_user=auto
        assert_script_run('cat /proc/cmdline');
        assert_script_run('grep "spectre_v2_user=auto" /proc/cmdline');

        #check cpu flags
        assert_script_run('cat /proc/cpuinfo');
        assert_script_run('grep "^flags.*ibpb.*" /proc/cpuinfo');
        assert_script_run('grep "^flags.*stibp.*" /proc/cpuinfo');

        #check sysfs
        assert_script_run( 'cat ' . $syspath . 'spectre_v2' );
        assert_script_run( 'cat '
              . $syspath
              . 'spectre_v2'
              . '| grep "^Mitigation: Indirect Branch Restricted Speculation.* IBPB: conditional,.* STIBP: conditional,.*"'
        );

        #chech dmesg
        record_info( 'spectre_v2_auto finish', "spectre_v2_user=auto finish and PASS." );
        remove_grub_cmdline_settings("spectre_v2_user=auto");

    #add spectre_v2_user=off parameter to disable spectre_v2 mitigation
    add_grub_cmdline_settings("spectre_v2_user=off");
    grub_mkconfig;

    #reboot and stand by
    reboot_and_wait( $self, 150 );
    record_info( 'off start', "spectre_v2_user=off start." );

    #recheck the status of spectre_v2_user=off
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "spectre_v2_user=off" /proc/cmdline');

    #check cpu flags
    assert_script_run('cat /proc/cpuinfo');
    assert_script_run('grep "^flags.*stibp.*" /proc/cpuinfo');
    assert_script_run('grep "^flags.*ibpb.*" /proc/cpuinfo');

    #check sysfs
    assert_script_run( 'cat ' . $syspath . 'spectre_v2' );
    assert_script_run(
        'cat ' . $syspath . 'spectre_v2' . '| grep ".*IBPB: disabled.*STIBP: disabled.*"' );

    #chech dmesg
    assert_script_run('dmesg | grep "User space: Vulnerable"');
    remove_grub_cmdline_settings("spectre_v2_user=off");
    record_info( 'off finish', "spectre_v2_user=off finish and PASS." );


    record_info( 'spectre_v2_user=on start', "spectre_v2_user=on start." );
    #add spectre_v2_user=on parameter to disable spectre_v2 mitigation
    add_grub_cmdline_settings("spectre_v2_user=on");
    grub_mkconfig;

    #reboot and stand by
    reboot_and_wait( $self, 150 );

    #recheck the status of spectre_v2_user=on
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "spectre_v2_user=on" /proc/cmdline');

    #check cpu flags
    assert_script_run('cat /proc/cpuinfo');
    assert_script_run('grep "^flags.*stibp.*" /proc/cpuinfo');
    assert_script_run('grep "^flags.*ibpb.*" /proc/cpuinfo');

    #check sysfs
    assert_script_run( 'cat ' . $syspath . 'spectre_v2' );
    assert_script_run(
        'cat ' . $syspath . 'spectre_v2' . '| grep ".*IBPB: always-on.*STIBP: forced.*"' );

    my $smt = script_output("cat /sys/devices/system/cpu/smt/active");
    if ( $smt eq 1 ) {
	    assert_script_run(
			    'dmesg | grep "Update user space SMT mitigation: STIBP always-on"');
    }else {
	    assert_script_run(
			    'dmesg | grep "Update user space SMT mitigation: STIBP off"');
    }
    assert_script_run('dmesg | grep "User space: Mitigation: STIBP protection"');
    assert_script_run('dmesg | grep "mitigation: Enabling always-on Indirect Branch Prediction Barrier"');
    remove_grub_cmdline_settings("spectre_v2_user=on");


#add spectre_v2_user=prctl parameter to disable spectre_v2 mitigation
    add_grub_cmdline_settings("spectre_v2_user=prctl");
    grub_mkconfig;

    #reboot and stand by
    reboot_and_wait( $self, 150 );
    record_info( 'prctl start',
        "spectre_v2_user=prctl start." );

    #recheck the status of spectre_v2_user=prctl
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "spectre_v2_user=prctl" /proc/cmdline');

    #check cpu flags
    assert_script_run('cat /proc/cpuinfo');
    assert_script_run('grep "^flags.*stibp.*" /proc/cpuinfo');
    assert_script_run('grep "^flags.*ibpb.*" /proc/cpuinfo');

    #check sysfs
    assert_script_run( 'cat ' . $syspath . 'spectre_v2' );
    assert_script_run( 'cat '
          . $syspath
          . 'spectre_v2'
          . '| grep "^.*IBPB: conditional.*STIBP: conditional.*"' );
    my $smt = script_output("cat /sys/devices/system/cpu/smt/active");
    assert_script_run(
        'dmesg | grep "User space: Mitigation: STIBP via prctl"');
    assert_script_run(
        'dmesg | grep "mitigation: Enabling conditional Indirect Branch Prediction Barrier"');
    remove_grub_cmdline_settings("spectre_v2_user=prctl");

    record_info( 'prctl finish', "spectre_v2_user=prctl finish and PASS." );



    record_info( 'spectre_v2_user=prctl,ibpb start',
        "spectre_v2_user=prctl,ibpb start." );
    #add spectre_v2_user=prctl,ibpb parameter to disable spectre_v2 mitigation
    add_grub_cmdline_settings("spectre_v2_user=prctl,ibpb");
    grub_mkconfig;

    #reboot and stand by
    reboot_and_wait( $self, 150 );

    #recheck the status of spectre_v2_user=prctl,ibpb
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "spectre_v2_user=prctl,ibpb" /proc/cmdline');

    #check sysfs
    assert_script_run( 'cat ' . $syspath . 'spectre_v2' );
    assert_script_run( 'cat '
          . $syspath
          . 'spectre_v2'
          . '| grep "^.*IBPB: always-on.*STIBP: conditional.*"' );
    my $smt = script_output("cat /sys/devices/system/cpu/smt/active");
    assert_script_run(
        'dmesg | grep "mitigation: Enabling always-on Indirect Branch Prediction Barrier"');
    assert_script_run(
        'dmesg | grep "User space: Mitigation: STIBP via prctl"');
    remove_grub_cmdline_settings("spectre_v2_user=prctl,ibpb");
    record_info( 'prctl,ibpb PASS', "spectre_v2_user=prctl,ibpb PASS." );


    record_info( 'spectre_v2_user=seccomp start',
        "spectre_v2_user=seccomp start." );
    #add spectre_v2_user=seccomp parameter to disable spectre_v2 mitigation
    add_grub_cmdline_settings("spectre_v2_user=seccomp");
    grub_mkconfig;

    #reboot and stand by
    reboot_and_wait( $self, 150 );

    #recheck the status of spectre_v2_user=seccomp
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "spectre_v2_user=seccomp" /proc/cmdline');

    #check sysfs
    assert_script_run( 'cat ' . $syspath . 'spectre_v2' );
    assert_script_run( 'cat '
          . $syspath
          . 'spectre_v2'
          . '| grep "^.*STIBP: conditional.*"' );
    my $smt = script_output("cat /sys/devices/system/cpu/smt/active");
    if ( $smt eq 1 ) {
	    assert_script_run( 'cat '
			    . $syspath
			    . 'spectre_v2'
			    . '| grep "^.*STIBP: conditional.*"' );
    }else {
	    assert_script_run( 'cat '
			    . $syspath
			    . 'spectre_v2'
			    . '| grep -v "STIBP:"' );
    }
    assert_script_run(
        'dmesg | grep "mitigation: Enabling conditional Indirect Branch Prediction Barrier"');
    assert_script_run(
        'dmesg | grep "User space: Mitigation: STIBP via seccomp and prctl"');
    remove_grub_cmdline_settings("spectre_v2_user=seccomp");
    record_info( 'prctl,ibpb PASS', "spectre_v2_user=seccomp PASS." );




    record_info( 'spectre_v2_user=seccomp,ibpb start',
        "spectre_v2_user=seccomp,ibpb start." );
    #add spectre_v2_user=seccomp,ibpb parameter to disable spectre_v2 mitigation
    add_grub_cmdline_settings("spectre_v2_user=seccomp,ibpb");
    grub_mkconfig;

    #reboot and stand by
    reboot_and_wait( $self, 150 );

    #recheck the status of spectre_v2_user=seccomp,ibpb
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "spectre_v2_user=seccomp,ibpb" /proc/cmdline');

    #check sysfs
    assert_script_run( 'cat ' . $syspath . 'spectre_v2' );
    assert_script_run( 'cat '
          . $syspath
          . 'spectre_v2'
          . '| grep "^.*IBPB: always-on.*STIBP: conditional.*"' );
    my $smt = script_output("cat /sys/devices/system/cpu/smt/active");
    assert_script_run(
        'dmesg | grep "mitigation: Enabling always-on Indirect Branch Prediction Barrier"');
    assert_script_run(
        'dmesg | grep "User space: Mitigation: STIBP via seccomp and prctl"');
    remove_grub_cmdline_settings("spectre_v2_user=seccomp,ibpb");
    record_info( 'prctl,ibpb PASS', "spectre_v2_user=seccomp,ibpb PASS." );



    record_info( 'spectre_v2_user=test start',
        "spectre_v2_user=test start." );
    #add spectre_v2_user=test parameter to disable spectre_v2 mitigation
    add_grub_cmdline_settings("spectre_v2_user=test");
    grub_mkconfig;

    #reboot and stand by
    reboot_and_wait( $self, 150 );

    #recheck the status of spectre_v2_user=test
    assert_script_run('cat /proc/cmdline');
    assert_script_run('grep "spectre_v2_user=test" /proc/cmdline');

    #check sysfs
    assert_script_run( 'cat ' . $syspath . 'spectre_v2' );
    assert_script_run( 'cat '
          . $syspath
          . 'spectre_v2'
          . '| grep "^.*IBPB: conditional.*STIBP: conditional.*"' );
    my $smt = script_output("cat /sys/devices/system/cpu/smt/active");
    assert_script_run (
        'dmesg | grep "Unknown user space protection option (test). Switching to AUTO select"');
    assert_script_run (
        'dmesg | grep "mitigation: Enabling conditional Indirect Branch Prediction Barrier"');
    assert_script_run(
        'dmesg | grep "User space: Mitigation: STIBP via seccomp and prctl"');
    remove_grub_cmdline_settings("spectre_v2_user=test");
    record_info( 'test PASS', "spectre_v2_user=test PASS." );


    assert_script_run(
"md /tmp/upload; cp $syspath* /tmp/upload; cp /proc/cmdline /tmp/upload; lscpu >/tmp/upload/cpuinfo; tar -jcvf /tmp/upload.tar.bz2 /tmp/upload"
    );
    remove_grub_cmdline_settings("nospectre_v2");
    remove_grub_cmdline_settings('spectre_v2=[a-z,]*');
    remove_grub_cmdline_settings('spectre_v2_user=[a-z,]*');
    grub_mkconfig;
    upload_logs '/tmp/upload.tar.bz2';
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
    remove_grub_cmdline_settings("nospectre_v2");
    remove_grub_cmdline_settings('spectre_v2=[a-z,]*');
    remove_grub_cmdline_settings('spectre_v2_user=[a-z,]*');
    grub_mkconfig;
    upload_logs '/tmp/upload.tar.bz2';
    $self->SUPER::post_fail_hook;
}

1;

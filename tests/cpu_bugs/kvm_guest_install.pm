# SUSE's openQA tests
#
# Copyright © 2009-2013 Bernhard M. Wiedemann
# Copyright © 2012-2018 SUSE LLC
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.

# Summary: KVM Guest install under the mitigation enable/disable
# Maintainer: James Wang <jnwang@suse.com>

use cpu_bugs;
use base "consoletest";
use bootloader_setup;
use ipmi_backend_utils;
use power_action_utils 'power_action';
use strict;
use testapi;
use utils;

my $syspath      = '/sys/devices/system/cpu/vulnerabilities/';
my $name         = get_var('VM_NAME');
my $install_url  = get_var('INSTALL_REPO');
my $logfile_path = get_var('VM_INST_LOG');
my $vm_shares    = get_var('VM_SHARES');
my $autoyast     = get_var('QA_AUTOYAST');
sub run {
    zypper_call("in libvirt-client");

    script_run( "mkdir -pv ${vm_shares}" );
    
    #remove old VM
    assert_script_run(
        'curl '
          . data_url("cpu_bugs/vm_install_script/sle-15/remove_vm.sh")
          . ' -o remove_vm.sh',
        60
    );
    assert_script_run('chmod 755 remove_vm.sh');
    script_run( './remove_vm.sh' . ' ' . $name );
    script_run( "rm ${vm_shares}/$name*" );

    assert_script_run(
        'curl '
          . data_url("cpu_bugs/vm_install_script/sle-15/create_vm_url.sh")
          . ' -o install_vm.sh',
        60
    );
    assert_script_run('chmod 755 install_vm.sh');
    assert_script_run(
        './install_vm.sh' . ' '
          . $name . ' '
          . $install_url . ' '
          . data_url($autoyast)
          . ' '
          . $logfile_path . ' '
          . $vm_shares . ' ',
        timeout => 3600
    );
    script_run(
        '(tail -f -n0 ' . $logfile_path . ' &) | grep -q "Welcome to SUSE"',
        600 );
    script_run( "virsh destroy $name", 600 );
    script_run( "sync",                600 );
    if (script_run("systemctl --all | grep \"apparmor\" | awk \'{print \$3}\' | grep '^not-found\$'") == 1) {
	    systemctl("disable apparmor");
	    systemctl("stop apparmor");
    }
    wait_idle(5);
    upload_logs $logfile_path;
    upload_logs 'remove_vm.sh';
    upload_logs 'install_vm.sh';
}

sub test_flags {
    return { milestone => 1, fatal => 0 };
}

sub post_fail_hook {
    my ($self) = @_;
    select_console 'root-console';
    assert_script_run(
        'curl '
          . data_url("cpu_bugs/vm_install_script/sle-15/remove_vm.sh")
          . ' -o remove_vm.sh',
        60
    );
    assert_script_run('chmod 755 remove_vm.sh');
    assert_script_run( './remove_vm.sh' . ' ' . $name );
    upload_logs $logfile_path;
    $self->SUPER::post_fail_hook;
}

1;

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
use lockapi;
use utils;
use mmapi;

my $syspath      = '/sys/devices/system/cpu/vulnerabilities/';
my $name         = get_var('VM_NAME');
my $install_url  = get_var('INSTALL_REPO');
my $logfile_path = get_var('VM_INST_LOG');
my $cpu          = get_var('CPU_FEATURE');
my $vm_pool      = get_var('VM_POOL');
my $source_host  = get_var("SOURCE_HOSTNAME");
my $dest_host    = get_var("DEST_HOSTNAME");

sub run {
    zypper_call("in libvirt-client");

    if ( get_var("MIGRATION_HOST") ) {
        my $children = get_children();
        my $child_id = ( keys %$children )[0];
        assert_script_run("cp /etc/exports{,.bak}");
        assert_script_run(
            "sed -i \"/^" . "\\" . ${vm_pool} . "/d\" /etc/exports" );
        assert_script_run(
            "virsh start $name",
            fail_message =>
"You need run install testcase to setup a KVM guest for migration."
        );

        #setup NFS and release a lock to notice client side
        zypper_call("in nfs-kernel-server");
        assert_script_run(
            "echo \"$vm_pool    *(rw,sync,no_root_squash)\" >>/etc/exports");
        systemctl("restart nfs-server.service");
        mutex_create 'nfs_server_ready';

        #waiting for client to finish inital operation
        mutex_wait( 'dest_host_ready', $child_id );

        #Do migrate
        assert_script_run(
            "virsh migrate --live $name --verbose qemu+tcp://$dest_host/system"
        );
        assert_script_run("virsh list | grep -v \"$name\"");
        assert_script_run("virsh list --all | grep \"${name}.*shut off\"");
        mutex_create 'migrate_done';

        #cleanup
        assert_script_run("cp /etc/exports{.bak,}");
    }
    elsif ( get_var("MIGRATION_DEST") ) {

        #access this machine without password
        assert_script_run("cp /etc/libvirt/libvirtd.conf{,.bak}");
        assert_script_run(
"sed -i 's/#listen_tcp = 1/listen_tcp = 1/g' /etc/libvirt/libvirtd.conf"
        );
        assert_script_run(
"sed -i 's/#auth_tcp = .*/auth_tcp = \"none\"/g' /etc/libvirt/libvirtd.conf"
        );
        systemctl("restart libvirtd");

        #wait server side is ready
        mutex_lock 'nfs_server_ready';
        zypper_call("in nfs-client");
        assert_script_run("mkdir -pv $vm_pool");
        assert_script_run("mount $source_host:$vm_pool $vm_pool");

        #tell server side client is ready
        mutex_create 'dest_host_ready';

        #waiting migrate until finish
        mutex_lock 'migrate_done';
        assert_script_run("virsh list | grep $name");

        #cleanup
        assert_script_run("cp /etc/libvirt/libvirtd.conf{.bak,}");
    }
}

sub test_flags {
    return { milestone => 1, fatal => 0 };
}

sub post_fail_hook {
    my ($self) = @_;
    select_console 'root-console';
    if ( get_var("MIGRATION_HOST") ) {
        assert_script_run(
            "sed -i \"/^" . "\\" . ${vm_pool} . "/d\" /etc/exports" );
        assert_script_run("cp /etc/exports{.bak,}");
    }
    elsif ( get_var("MIGRATION_DEST") ) {
        assert_script_run("cp /etc/libvirt/libvirtd.conf{.bak,}");
    }
    assert_script_run('virsh list > /tmp/virsh_list.log');
    upload_logs("/tmp/virsh_list.log");
    $self->SUPER::post_fail_hook;
}

1;

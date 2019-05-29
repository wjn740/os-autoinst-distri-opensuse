package nfs_common;
use mmapi;
use testapi;
use strict;
use warnings;
use utils qw(systemctl file_content_replace);
use Utils::Systemd 'disable_and_stop_service';
use mm_network;
use version_utils;


our @ISA    = qw(Exporter);
our @EXPORT = qw(server_configure_network try_nfsv2 prepare_exports yast_handle_firewall add_shares
  mount_export client_common_tests check_nfs_ready yast2_server_initial);

sub server_configure_network {
    # Configure static IP for client/server test
    configure_default_gateway;
    configure_static_ip('10.0.2.101/24');
    configure_static_dns(get_host_resolv_conf());

    if (is_sle('15+')) {
        record_soft_failure 'boo#1130093 No firewalld service for nfs-kernel-server';
        disable_and_stop_service('firewalld');
    }
}

sub try_nfsv2 {
    # Try that NFSv2 is disabled by default
    systemctl 'start nfsserver';
    assert_script_run "cat /proc/fs/nfsd/versions | grep '\\-2'";
    file_content_replace("/etc/sysconfig/nfs", "MOUNTD_OPTIONS=.*" => "MOUNTD_OPTIONS=\"-V2\"", "NFSD_OPTIONS=.*" => "NFSD_OPTIONS=\"-V2\"");
    systemctl 'restart nfsserver';
    assert_script_run "cat /proc/fs/nfsd/versions | grep '+2'";

    # Disable NFSv2 again
    file_content_replace("/etc/sysconfig/nfs", "MOUNTD_OPTIONS=.*" => "MOUNTD_OPTIONS=\"\"", "NFSD_OPTIONS=.*" => "NFSD_OPTIONS=\"\"");
    systemctl 'stop nfsserver';
}

sub prepare_exports {
    my ($rw, $ro) = @_;
    my $ne = "/srv/dir/";

    # Create a directory and place a test file in it
    assert_script_run "mkdir ${rw} && echo success > ${rw}/file.txt";

    # Create also hardlink, symlink and do bindmount
    assert_script_run "( mkdir ${ne} ${rw}/bindmounteddir && ln -s ${ne} ${rw}/symlinkeddir && mount --bind ${ne} ${rw}/bindmounteddir )";
    assert_script_run "( echo example > ${ne}/example && ln ${ne}/example ${rw}/hardlinkedfile & ln -s ${ne}example ${rw}/symlinkedfile )";
    assert_script_run "echo secret > ${rw}/secret.txt && chmod 740 ${rw}/secret.txt";

    # Create large file and count its md5sum
    assert_script_run "fallocate -l 1G ${rw}/random";
    assert_script_run "md5sum ${rw}/random | cut -d' ' -f1 > ${rw}/random.md5sum";

    # Create read only directory - this is different between v3 and v4
    assert_script_run "mkdir ${ro} && echo success > ${ro}/file.txt";
}

sub yast_handle_firewall {
    if (is_sle('<15')) {
        send_key 'alt-f';    # Open port in firewall
        assert_screen 'nfs-firewall-open';
    }
    else {
        save_screenshot;
    }
}

sub add_shares {
    my ($rw, $ro) = @_;

    # Add rw share
    send_key 'alt-d';
    assert_screen 'nfs-new-share';
    type_string $rw;
    send_key 'alt-o';

    # Permissions dialog
    assert_screen 'nfs-share-host';
    send_key 'tab';
    # Change 'ro,root_squash' to 'rw,fsid=0,no_root_squash,...'
    send_key 'home';
    send_key 'delete';
    send_key 'delete';
    send_key 'delete';
    type_string "rw,fsid=0,no_";
    send_key 'alt-o';

    # Saved
    assert_screen 'nfs-share-saved';

    # Add ro share
    send_key 'alt-d';
    assert_screen 'nfs-new-share';
    type_string $ro;
    send_key 'alt-o';

    # Permissions dialog
    assert_screen 'nfs-share-host';
    send_key 'alt-o';

    # Saved
    assert_screen 'nfs-share-saved';
}

sub mount_export {
    script_run 'mount|grep nfs';
    assert_script_run 'cat /etc/fstab | grep nfs';

    # script_run is using bash return logic not perl logic, 0 is true
    if ((script_run('grep "success" /tmp/nfs/client/file.txt', 90)) != 0) {
        record_soft_failure 'boo#1006815 nfs mount is not mounted';
        assert_script_run 'mount /tmp/nfs/client';
        assert_script_run 'grep "success" /tmp/nfs/client/file.txt';
    }
}

sub client_common_tests {
    # remove added nfs from /etc/fstab
    assert_script_run 'sed -i \'/nfs/d\' /etc/fstab';

    # compare saved and current fstab, should be same
    assert_script_run 'diff -b /etc/fstab fstab_before';

    # compare last line, should be not deleted
    assert_script_run 'diff -b <(tail -n1 /etc/fstab) <(tail -n1 fstab_before)';

    # Remote symlinked directory is visible, removable but not accessible
    assert_script_run "ls -la /tmp/nfs/client/symlinkeddir";
    assert_script_run "! ls -la /tmp/nfs/client/symlinkeddir/";
    assert_script_run "! touch /tmp/nfs/client/symlinkeddir/x";
    assert_script_run "rm /tmp/nfs/client/symlinkeddir";

    # Remote bind-mounted directory is visible, accessible but isn't removable
    assert_script_run "ls -la /tmp/nfs/client/bindmounteddir/";
    assert_script_run "touch /tmp/nfs/client/bindmounteddir/x";
    assert_script_run "! rm -rf /tmp/nfs/client/bindmounteddir";

    # Remote hardlinks is visible, accessible and removable
    assert_script_run "ls -la /tmp/nfs/client/hardlinkedfile";
    assert_script_run "cat /tmp/nfs/client/hardlinkedfile";
    assert_script_run "echo x > /tmp/nfs/client/hardlinkedfile";
    assert_script_run "rm /tmp/nfs/client/hardlinkedfile";

    # Remote symlink is visible but not readable, nor writable, nor removable
    assert_script_run "ls -la /tmp/nfs/client/symlinkedfile";
    assert_script_run "! cat /tmp/nfs/client/symlinkedfile";
    assert_script_run "! echo x > /tmp/nfs/client/symlinkedfile";
    assert_script_run "rm /tmp/nfs/client/symlinkedfile";

    # Copy large file from NFS and test it's checksum
    assert_script_run "time cp /tmp/nfs/client/random /tmp/", 120;
    assert_script_run "md5sum /tmp/random | cut -d' ' -f1 > /tmp/random.md5sum";
    assert_script_run "diff /tmp/nfs/client/random.md5sum /tmp/random.md5sum";
}

sub check_nfs_ready {
    my ($rw, $ro) = @_;

    assert_script_run "exportfs | grep '${rw}\\|${ro}'";
    assert_script_run "cat /etc/exports | tr -d ' \\t\\r' | grep '${rw}\\*(rw,\\|${ro}\\*(ro,'";
    assert_script_run "cat /proc/fs/nfsd/exports";

    if ((script_run('systemctl is-enabled nfsserver')) != 0) {
        record_info 'disabled', 'The nfsserver unit is disabled';
        systemctl 'enable nfsserver';
    }
    if ((script_run('systemctl is-active nfsserver')) != 0) {
        record_info 'stopped', 'The nfsserver unit is stopped';
        systemctl 'start nfsserver';
    }
}

sub yast2_server_initial {
    do {
        assert_screen([qw(nfs-server-not-installed nfs-firewall nfs-config)]);
        # install missing packages as proposed
        if (match_has_tag('nfs-server-not-installed') or match_has_tag('nfs-firewall')) {
            send_key 'alt-i';
        }
    } while (not match_has_tag('nfs-config'));
}

1;

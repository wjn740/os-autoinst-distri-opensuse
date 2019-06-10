# SUSE's openQA tests
#
# Copyright © 2018 SUSE LLC
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.
#
#
# Summary: switch IPMI to QEMU
# Maintainer: James Wang <jnwang@suse.com>

use Mitigation;
use base "consoletest";
use bootloader_setup;
use ipmi_backend_utils;
use power_action_utils 'power_action';
use strict;
use testapi;
use utils;
use version_utils 'is_sle';
my $cliect_ini_url = get_var('CLIENT_INI');
my $webui_hostname = get_var('WEBUI_HOSTNAME');
my $nfs_hostname = get_var('NFS_HOSTNAME');
my $qemu_worker_class = get_var('QEMU_WORKER_CLASS');
sub run {
	my $self = shift;
	script_run("systemctl disable apparmor.service");
	script_run("aa-teardown");
	script_run("zypper rr devel_languages_perl devel_openQA devel_openQA_SLE-12 devel_openQA_SLE-15");
	if(is_sle(">=15")) {
		zypper_call("ar http://download.opensuse.org/repositories/devel:/languages:/perl/SLE_15/devel:languages:perl.repo");
		zypper_call("ar http://download.opensuse.org/repositories/devel:/openQA/SLE_15/devel:openQA.repo");
		zypper_call("ar http://download.opensuse.org/repositories/devel:/openQA:/SLE-15/SLE_15/devel:openQA:SLE-15.repo");
	}elsif(is_sle(">=12")) {
		zypper_call("ar http://download.opensuse.org/repositories/devel:/languages:/perl/SLE_12_SP4/devel:languages:perl.repo");
		zypper_call("ar http://download.opensuse.org/repositories/devel:/openQA/SLE_12_SP4/devel:openQA.repo");
		zypper_call("ar http://download.opensuse.org/repositories/devel:/openQA:/SLE-12/SLE_12_SP4/devel:openQA:SLE-12.repo");
	}
        script_run("zypper -n --gpg-auto-import-keys ref");
        script_run("zypper -n dup");
	zypper_call("in openQA-worker");
	zypper_call("in --replacefiles perl-DBD-SQLite");

	#NFS mount
	#assert_script_run("mount -t nfs $nfs_hostname:/var/lib/openqa/share /var/lib/openqa/share");
	
	#Rsync
	assert_script_run("echo \"[http://$nfs_hostname]\" >> /etc/openqa/workers.ini");
	assert_script_run("echo \"TESTPOOLSERVER = rsync://$nfs_hostname/tests\" >>/etc/openqa/workers.ini");
	

        assert_script_run("sed -i '/^#.*global/s/^#//' /etc/openqa/workers.ini");
        assert_script_run("sed -i '/^HOST =.*/d' /etc/openqa/workers.ini");
	if (script_run("grep \"^#.*HOST.*=.*\" /etc/openqa/workers.ini") == 0) {
        	assert_script_run("sed -i '/^#.*HOST.*=.*/a HOST = $webui_hostname' /etc/openqa/workers.ini");
	}else {
        	assert_script_run("sed -i '/^\\[global\\]/a HOST = $webui_hostname' /etc/openqa/workers.ini");
	}
        assert_script_run("sed -i '/^WORKER_CLASS =.*/d' /etc/openqa/workers.ini");
        assert_script_run("sed -i '/WORKER_HOSTNAME =.*/a WORKER_CLASS = $qemu_worker_class' /etc/openqa/workers.ini");
    assert_script_run(
        'curl '
          . $cliect_ini_url
          . ' -o /etc/openqa/client.conf',
        60
    );
        script_run('systemctl start openqa-worker@1');
        script_run('systemctl start openqa-worker@2');
        script_run('systemctl start openqa-worker@3');
        script_run('systemctl start openqa-worker@4');
        script_run('systemctl start openqa-worker@5');
        script_run('systemctl start openqa-worker@6');
        script_run('systemctl start openqa-worker@7');
        script_run('systemctl start openqa-worker@8');
}

sub test_flags {
    return { milestone => 1, fatal => 0 };
}

sub post_fail_hook {
    my ($self) = @_;
}

1;


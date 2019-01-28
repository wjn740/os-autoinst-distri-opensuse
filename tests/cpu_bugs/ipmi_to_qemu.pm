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

use cpu_bugs;
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

	script_run("yast virtualization");
	send_key 'alt-k';
	send_key 'alt-v';
	send_key 'alt-a';

	assert_screen([qw(yast_virtualization_installed yast_virtualization_bridge)], 600);
	assert_screen("yast_virtualization_accept");
	send_key 'alt-y';
	if (match_has_tag('yast_virtualization_bridge')) {
	# select yes
		send_key 'alt-y';
		assert_screen 'yast_virtualization_installed', 60;
	}
	send_key 'alt-o';
	script_run("systemctl disable apparmor.service");
	script_run("aa-teardown");
	script_run("zypper rr devel_languages_perl devel_openQA devel_openQA_SLE-12 devel_openQA_SLE-15");
	if(is_sle(">=15")) {
		zypper_call("ar http://download.opensuse.org/repositories/devel:/languages:/perl/SLE_15/devel:languages:perl.repo");
		zypper_call("ar http://download.opensuse.org/repositories/devel:/openQA/SLE_15/devel:openQA.repo");
		zypper_call("ar http://download.opensuse.org/repositories/devel:/openQA:/SLE-15/SLE_15/devel:openQA:SLE-15.repo");
	}elsif(is_sle(">=12")) {
		zypper_call("ar http://download.opensuse.org/repositories/devel:/languages:/perl/SLE_12_SP3/devel:languages:perl.repo");
		zypper_call("ar http://download.opensuse.org/repositories/devel:/openQA/SLE_12_SP3/devel:openQA.repo");
		zypper_call("ar http://download.opensuse.org/repositories/devel:/openQA:/SLE-12/SLE_12_SP3/devel:openQA:SLE-12.repo");
	}
        script_run("zypper -n --gpg-auto-import-keys ref");
	zypper_call("in openQA-worker");
	zypper_call("in --replacefiles perl-DBD-SQLite");

        assert_script_run("mount -t nfs $nfs_hostname:/var/lib/openqa/share /var/lib/openqa/share");

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

1;


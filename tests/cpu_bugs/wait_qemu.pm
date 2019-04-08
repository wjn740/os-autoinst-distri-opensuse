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
	zypper_call("in netcat-openbsd");
	script_run("echo Done | nc ph044.qa2.suse.asia 12345");
	
}

1;


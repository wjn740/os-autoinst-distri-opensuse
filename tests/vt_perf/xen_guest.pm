# SUSE's openQA tests
#
# Copyright © 2019 SUSE LLC
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.
#
# This is testsuite run on XEN dom0. Makes sure testsuite could run properly.
# The following example is Dell machine(They usually use com2 as serial device);
# Please add the following parameters into XEN command-line.
# console=com2
#
# Please add the following parameters into Dom0 command-line.
# console=hvc0 console=ttyS0
#
# Please modify grub serial command:
# GRUB_SERIAL_COMMAND="serial --unit=1 --speed=115200 --parity=no --word=8"


# Summary: VT perf testsuite on XEN PV/HVM Guest testing
# Maintainer: James Wang <jnwang@suse.com>

use warnings;
use strict;
use base "opensusebasetest";
use Utils::Backends 'use_ssh_serial_console';
use bootloader_setup qw(grub_mkconfig change_grub_config add_grub_cmdline_settings remove_grub_cmdline_settings grep_grub_settings set_framebuffer_resolution set_extrabootparams_grub_conf);
use Mitigation;
use ipmi_backend_utils;
use power_action_utils 'power_action';
use testapi;
use utils;


my $syspath      = '/sys/devices/system/cpu/vulnerabilities/';
my $name         = get_var('VM_NAME');
my $install_url  = get_var('INSTALL_REPO');
my $logfile_path = get_var('VM_INST_LOG');
my $cpu          = get_var('CPU_FEATURE');
my $vm_pool      = get_var('VM_POOL');
my $vm_shares    = get_var('VM_SHARES');
my $source_host  = get_var("SOURCE_HOSTNAME");
my $dest_host    = get_var("DEST_HOSTNAME");
my $subname      = "";
my $cpu_1        = "";
my $git_repo_url = get_required_var("MITIGATION_GIT_REPO");
my $git_user	 = get_required_var("MITIGATION_GIT_REPO_USER");
my $git_pass	 = get_required_var("MITIGATION_GIT_REPO_PASS");
my $git_branch_name = get_required_var("MITIGATION_GIT_BRANCH_NAME");
my $deploy_script = get_required_var("DEPLOY_SCRIPT");
my $run_id = get_required_var("RUN_ID");
my $password = get_required_var("GUEST_PASSWORD");
my $hypervisor_mitigation_off = get_var("HYPERVISOR_MITIGATION_OFF", 0);
my $xen_guest_type = get_var("XEN_GUEST_TYPE", 'pv');

sub run {
	my $self = shift;

	assert_script_run("test -e /proc/xen", fail_message => 'Current system is not a xen hypervisor dom0');


	#Prepare mitigations-testsuite.git
	assert_script_run("git config --global http.sslVerify false");
	assert_script_run("rm -rf mitigation-testsuite");
	assert_script_run("git clone -q --single-branch -b $git_branch_name --depth 1 $git_repo_url");
	assert_script_run("pushd mitigation-testsuite");
	assert_script_run("git status");
	assert_script_run("PAGER= git log -1");

	##ucode update is disable by default on XEN
	#my $ret = script_run("xl info | grep \"xen_commandline\" | grep \"ucode=scan\"");
	##if ($ret) {
	##	add_grub_xen_cmdline_settings("ucode=scan");
	##}
	#my $ret = script_run("xl info | grep \"xen_commandline\" | grep \"dom0_max_vcpus=8 dom0_mem=8G,max:8G\"");
	##if ($ret) {
	##	add_grub_xen_cmdline_settings("dom0_max_vcpus=8 dom0_mem=8G,max:8G");
	##}

	##check if XEN Hypervisor set spec-ctrl=off and dom5's kernel set mitigations=off
	##If yes, we set to default mode.
	#$ret = script_run("xl info | grep \"xen_commandline\" | grep \"spec-ctrl=off\"");
	#if ($ret eq 0) {
	#	#Sometime parameter be writen on the line of GRUB_CMDLINE_LINUX
	#	assert_script_run("sed -i '/GRUB_CMDLINE_XEN_DEFAULT=/s/spec-ctrl=off/ /g' /etc/default/grub");

	#	#remove_xen_grub_cmdline_settings("mitigations=off");

	#}
	#$ret = script_run("grep \"mitigations=off\" /proc/cmdline");
	#if ($ret eq 0) {
	#	#Sometime parameter be writen on the line of GRUB_CMDLINE_LINUX
	#	assert_script_run("sed -i '/GRUB_CMDLINE_LINUX=/s/mitigations=off/ /g' /etc/default/grub");

	#	assert_script_run("sed -i '/GRUB_CMDLINE_LINUX_XEN_REPLACE_DEFAULT=/s/mitigations=off/ /g' /etc/default/grub");

	#	#This remove can't make sure clean all lines.
	#	remove_grub_cmdline_settings("mitigations=off");

	#}
	#reboot make new kernel command-line available
	#Mitigation::reboot_and_wait($self, 150);

	#check new kernel command-line
	#$ret = script_run("grep \"mitigations=off\" /proc/cmdline");
	#if ($ret eq 0) {
	#	die 'remove "mitigations=off" from kernel command-line failed';
	#}


	assert_script_run("pushd ~/mitigation-testsuite");
	if ($xen_guest_type eq 'hvm') {
		assert_script_run("sed -i 's#vm_type=.*#vm_type=hvm#g' test.config");
	}
	assert_script_run("password=${password} sh main.sh", timeout => 3600);

}

sub test_flags {
    return { milestone => 1, fatal => 0 };
}

sub post_fail_hook {
	    my ($self) = @_;
	    select_console 'root-console';
}

1;

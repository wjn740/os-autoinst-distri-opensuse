# SUSE's openQA tests
#
# Copyright © 2009-2013 Bernhard M. Wiedemann
# Copyright © 2012-2019 SUSE LLC
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.

# Summary: CPU BUGS on Linux kernel check
# Maintainer: James Wang <jnwang@suse.com>
#
#
package Mitigation;

use strict;
use warnings;

use base "Exporter";
use Exporter;

use testapi;
use utils;

use Utils::Backends 'use_ssh_serial_console';
use bootloader_setup qw(change_grub_config add_grub_cmdline_settings remove_grub_cmdline_settings grep_grub_settings grub_mkconfig set_framebuffer_resolution set_extrabootparams_grub_conf);
use ipmi_backend_utils;
use power_action_utils 'power_action';


sub reboot_and_wait {
    my ( $self, $timeout ) = @_;
    power_action( 'reboot', textmode => 1, keepconsole => 1 );
    if ( check_var( 'BACKEND', 'ipmi' ) ) {
        switch_from_ssh_to_sol_console( reset_console_flag => 'on' );
        check_screen( 'login_screen', $timeout );
        use_ssh_serial_console;
    }
    else {
        $self->wait_boot( textmode => 1, ready_time => 300 );
        select_console 'root-console';
    }
}

our $syspath = '/sys/devices/system/cpu/vulnerabilities/';
my @mitigations_list = (
	{
		name => "meltdown",
		CPUID => hex '20000000',
		IA32_ARCH_CAPABILITIES => 1, #bit0 -- RDCL_NO
		parameter => 'pti',
		cpuflags => ['pti'],
		sysfs => {
			"on" => "Mitigation: PTI", 
			"off" => "Vulnerable", 
			"auto" => "Mitigation: PTI",
			"default" => "Mitigation: PTI", 
		},
		dmesg => {
			"on" => "Kernel/User page tables isolation: enabled", 
			"off" => "", 
			"auto" => "Kernel/User page tables isolation: enabled",
			"default" => "Kernel/User page tables isolation: enabled", 
		},
		cmdline => [
			"on",
			"off",
			"auto",
		],
		lscpu => {
			"on" => "pti", 
			"off" => "", 
			"auto" => "pti",
		},
	},
	{
		name => "spectre_v2",
		CPUID => hex '4000000',
		IA32_ARCH_CAPABILITIES => 2, #bit1 -- EIBRS
		parameter => 'spectre_v2',
		cpuflags => ['ibrs', 'ibpb', 'stibp'],
		sysfs => {
				"on" => "Mitigation: Indirect Branch Restricted Speculation.*IBPB: always-on, IBRS_FW, STIBP: forced*", 
				"off" => "Vulnerable,.*IBPB: disabled,.*STIBP: disabled", 
				"auto" => "Mitigation: Indirect Branch Restricted Speculation.*IBPB: conditional, IBRS_FW, STIBP: conditional,*",
				"retpoline" => "Mitigation: Full generic retpoline.*",
				"ibrs" => "Mitigation: Indirect Branch Restricted Speculation.*"
				},
		cmdline => [
				"on",
				"off",
				"auto",
				"retpoline",
				],
	},
	{
		name => "spectre_v2_user",
		CPUID => hex 'C000000',
		IA32_ARCH_CAPABILITIES => 2, #bit1 -- EIBRS
		parameter => 'spectre_v2',
		cpuflags => ['ibpb', 'stibp'],
		sysfs => {
				"on" => "Mitigation: Indirect Branch Restricted Speculation.* IBPB: always-on,.* STIBP: forced,.*", 
				"off" => ".*IBPB: disabled,.*STIBP: disabled", 
				"prctl" => ".*IBPB: conditional.*STIBP: conditional.*",
				"prctl,ibpb" => ".*IBPB: always-on.*STIBP: conditional.*",
				"seccomp" => ".*STIBP: conditional.*",
				"seccomp,ibpb" => ".*IBPB: always-on.*STIBP: conditional.*",
				"auto" => "Mitigation: Indirect Branch Restricted Speculation.* IBPB: conditional,.* STIBP: conditional,.*",
				},
		cmdline => [
				"on",
				"off",
				"prctl",
				"prctl,ibpb",
				"seccomp",
				"seccomp,ibpb",
				"auto",
				],
	},
	{
		name => "l1tf",
		CPUID => hex '10000000',
		IA32_ARCH_CAPABILITIES => 8, #bit3 --SKIP_L1TF_VMENTRY
		parameter => 'l1tf',
		cpuflags => ['flush_l1d'],
		sysfs => {
			"full" => "Mitigation: PTE Inversion; VMX: cache flushes, SMT disabled", 
			"full,force" => "Mitigation: PTE Inversion; VMX: cache flushes, SMT disabled", 
			"flush" => "Mitigation: PTE Inversion; VMX: conditional cache flushes, SMT vulnerable", 
			"flush,nosmt" => "Mitigation: PTE Inversion; VMX: conditional cache flushes, SMT disabled", 
			"flush,nowarn" => "Mitigation: PTE Inversion; VMX: conditional cache flushes, SMT vulnerable",
			"off" => "Mitigation: PTE Inversion; VMX: vulnerable",
			"default" => "Mitigation: PTE Inversion; VMX: conditional cache flushes, SMT vulnerable", 
		},
		cmdline => [
			"full",
			"full,force",
			"flush",
			"flush,nosmt",
			"flush,nowarn",
			"off",
		],
	},
	{
		name => "spectre_v4",
		CPUID => hex '80000000',
		IA32_ARCH_CAPABILITIES => 16, #bit4 --SSB_NO 
		parameter => 'spectre_v4',
		cpuflags => ['ssbd'],
		sysfs => {
			"on" => "Mitigation: Speculative Store Bypass disabled",
			"off" => "Vulnerable",
			"auto" => "Mitigation: Speculative Store Bypass disabled via prctl and seccomp", 
			"prctl" => "Mitigation: Speculative Store Bypass disabled via prctl", 
			"seccomp" => "Mitigation: Speculative Store Bypass disabled via prctl and seccomp",
			"default" => "Mitigation: Speculative Store Bypass disabled via prctl and seccomp",
		},
		cmdline => [
			"on",
			"off",
			"auto",
			"prctl",
			"seccomp",
		],
	},
	{
		name => "mds",
		CPUID => hex '20000000',
		IA32_ARCH_CAPABILITIES => 32, #bit5 --MDS_NO
		parameter => 'mds',
		cpuflags => ['md_clear'],
		sysfs => {
			"full" => "Mitigation: Clear CPU buffers; SMT vulnerable",
			"full,nosmt" => "Mitigation: Clear CPU buffers; SMT disabled",
			"off" => "Vulnerable; SMT vulnerable", 
			"default" => "Mitigation: Clear CPU buffers; SMT vulnerable",
		},
		cmdline => [
			"full",
			"full,nosmt",
			"off",
		],
	},
);

sub new{

	my $class = shift;

	my $self = {
		'name' => shift,
		'CPUID' => shift,
		'IA32_ARCH_CAPABILITIES' => shift,
    		'parameter' => shift,
    		'sysfs_name' => shift
	};

	bless $self, $class;

	return $self;
}

sub Name {
	my ($self, $value) = @_;
	if (@_ == 2) {
		$self->{'name'} = $value;
	}
	return $self->{'name'};
}

sub Parameter {
	my ($self, $value) = @_;
	if (@_ == 2) {
		$self->{'parameter'} = $value;
	}
	return $self->{'Parameter'};
}
sub Sysfs {
	my ($self, $value) = @_;
	if (@_ == 2) {
		$self->{'sysfs_name'} = $value;

	}
	return $self->{'sysfs_name'};
}
sub CPUID {
	my ($self, $value) = @_;
	if (@_ == 2) {
		$self->{'CPUID'} = $value;
	}
	return $self->{'CPUID'};
}

sub MSR {
	my ($self, $value) = @_;
	if (@_ == 2) {
		$self->{'IA32_ARCH_CAPABILITIES'} = $value;
	}
	return $self->{'IA32_ARCH_CAPABILITIES'};
}

sub load_cpuid {
	my $self = shift;
	zypper_call("in cpuid");
	my $edx = hex script_output(
		"cpuid -1 -l 7 -s 0 -r | awk \'{print \$6}\' | awk -F \"=\" \'{print \$2}\' | tail -n1"
	);
	$self->CPUID($edx);
}

sub load_msr {
	my $self = shift;
	my $edx = script_output(
		"perl -e \'open(M,\"<\",\"/dev/cpu/0/msr\") and seek(M,0x10a,0) and read(M,\$_,8) and print\' | od -t u8 -A n"
	);
	$self->MSR($edx);
}


sub show {
	my $self = shift;
	print $self->Name(),",";
	print $self->CPUID(),",";
	print $self->MSR(),"\n";
}

sub vulnerabilities {
	my $self = shift;
	my $item;
	foreach $item (@mitigations_list) {
		if ($item->{'name'} eq $self->Name()) {
			if ($item->{'CPUID'} & $self->CPUID()) {
				if ($item->{'IA32_ARCH_CAPABILITIES'} & $self->MSR()) {
					record_info("Not Affected", "This machine needn't be test.");
					return 0; #Not Affected
				}else {
					record_info("vulnerable", "This machine need to test.");
					return 1; #Affected
				}
			}
			record_info("vulnerable", "This machine need to test.");
			return 1;
		}
	}
}

sub sysfs{
	my ($self,$value) = @_;
	my $item;
	my $p;
	foreach $item (@mitigations_list) {
		if ($item->{'name'} eq $self->Name()) {
			if (@_ == 2) {
  				return $item->{'sysfs'}->{$value};
			}
  			return $item->{'sysfs'};

		}
	}
}

sub dmesg{
	my $self = shift;
  my $item;
  my $p;
  foreach $item (@mitigations_list) {
		if ($item->{'name'} eq $self->Name()) {
      for $p (keys %{$item->{'dmesg'}}) {
          print "dmesg ",$self->Name,"\n";
          print $item->{'dmesg'}->{$p},"\n";
      }
    }
  }
}

sub cmdline{
	my $self = shift;
	my $item;
	my $p;
	foreach $item (@mitigations_list) {
		if ($item->{'name'} eq $self->Name()) {
			return $item->{'cmdline'};
		}
	}
}

sub lscpu{
	my $self = shift;
  my $item;
  my $p;
  foreach $item ($self->getAllmitigationslist) {
		if ($item->{'name'} eq $self->Name()) {
      for $p (keys %{$item->{'lscpu'}}) {
          print "lscpu ",$self->Name,"\n";
          print $item->{'lscpu'}->{$p},"\n";
      }
    }
  }
}

sub getAllmitigationslist {
  return @mitigations_list;
}


sub check_default_status{
  my $self = shift;
  assert_script_run('cat /proc/cmdline');
  my $ret = script_run('grep -v "' . $self->{'parameter'} . '=[a-z]*" /proc/cmdline');
  my $ret1 = script_run('grep -v "' . "mitigations" . '=[a-z]*" /proc/cmdline');
  if ( $ret ne 0 or $ret1 ne 0) { 
    remove_grub_cmdline_settings($self->{'parameter'} . "=[a-z]*");
    remove_grub_cmdline_settings("mitigations=[a-z]*");
    grub_mkconfig();
    reboot_and_wait( $self, 150 );
    assert_script_run('grep -v "' . $self->{'parameter'} . '=off" /proc/cmdline');
  }   
}

sub check_cpu_flags {
  my $self = shift;
  my $reverse = shift;
  my $flag;
  assert_script_run('cat /proc/cpuinfo');
  foreach $flag (@{$self->{'cpuflags'}}) {
    assert_script_run('cat /proc/cpuinfo | grep "^flags.*' . $self->{'cpuflags'} .'.*"');
    if ($reverse) {
    	assert_script_run('cat /proc/cpuinfo | grep -v "^flags.*' . $self->{'cpuflags'} .'.*"');
    }
  }
}

sub check_sysfs {
	my ($self, $value) = @_;
	assert_script_run( 'cat ' . $syspath . $self->Sysfs() );
	if (@_ == 2) {
		assert_script_run(
			'cat ' . $syspath . $self->Sysfs() . '| grep ' . '"'. $self->sysfs($value) . '"' );
	}
}

sub check_dmesg {
  my $self = shift;
  my $value = shift; #the value of kernel parameter
  my $string;

  foreach $string ($self->{'dmesg'}->{$value}) {
    assert_script_run(
      'dmesg | grep "' . $string . '"');
  }
}

sub check_cmdline {
	my $self =shift;
    	assert_script_run(
      		'cat /proc/cmdline'
	);

}

sub check_one_parameter_value{
	#testing each parameter.
	my $self = shift;
	my $cmd = shift;
	if ($cmd) {
		$self->add_parameter($cmd);
		$self->check_cpu_flags();
		$self->check_sysfs($cmd);
		$self->remove_parameter($cmd);
	}
}



sub check_each_parameter_value {
#testing each parameter.
  my $self = shift;
  my $cmd;
  foreach $cmd (@{$self->cmdline()}) {
	record_info("$self->{'name'}=$cmd", "Mitigation $self->{'name'} = $cmd  testing start.");
	$self->add_parameter($cmd);
	$self->check_cpu_flags();
	$self->check_cmdline();
	$self->check_sysfs($cmd);
	$self->remove_parameter($cmd);
  }
}


sub add_parameter{
  my $self = shift;
  my $value = shift;
  add_grub_cmdline_settings($self->{'parameter'} .'='. $value);
  grub_mkconfig();
  reboot_and_wait( $self, 150 );
}

sub remove_parameter{
  my $self = shift;
  my $value = shift;
  remove_grub_cmdline_settings($self->{'parameter'} .'='. $value);
}


sub do_test {
	my $self = shift;
	#load current cpu info
	$self->load_msr();
	$self->load_cpuid();
	#check applicability
	my $ret = $self->vulnerabilities();
	if ($ret == 0) {
		record_info('INFO', "This CPU is not affected by $self->{'name'}.");
		return 0;
	}else {
		record_info('INFO', "Mitigation $self->{'name'} testing start.");
	}
	#check system default status
	#and prepare the command line parameter for next testings
	$self->check_default_status();
	#
	$self->check_cpu_flags();
	$self->check_sysfs("default");

	$self->check_each_parameter_value();
}


1;

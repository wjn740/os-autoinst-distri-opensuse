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
use bootloader_setup qw(change_grub_config grep_grub_settings grub_mkconfig set_framebuffer_resolution set_extrabootparams_grub_conf);
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
    cpuflags => ('pti'),
		sysfs => {
				"on" => "Mitigation: PTI", 
				"off" => "Vulnerable", 
				"auto" => "Mitigation: PTI",
				},
		dmesg => {
				"on" => "Kernel/User page tables isolation: enabled", 
				"off" => "", 
				"auto" => "Kernel/User page tables isolation: enabled",
				},
		cmdline => {
				"on" => "pti=on", 
				"off" => "pti=off", 
				"auto" => "pti=auto",
				},
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
		SLE12SP4 => {
				"on" => "Mitigation: Indirect Branch Restricted Speculation.*", 
				"off" => "Vulnerable,.*IBPB: disabled,.*STIBP: disabled", 
				"auto" => "Mitigation: Indirect Branch Restricted Speculation.*",
				"retpoline" => "Mitigation: Full generic retpoline.*",
				"ibrs" => "Mitigation: Indirect Branch Restricted Speculation.*"
				},
		SLE12SP5 => {
				"on" => "Mitigation: Indirect Branch Restricted Speculation.*", 
				"off" => "Vulnerable,.*IBPB: disabled,.*STIBP: disabled", 
				"auto" => "Mitigation: Indirect Branch Restricted Speculation.*",
				"retpoline" => "Mitigation: Full generic retpoline.*",
				},
	},
	{
		name => "spectre_v2_user",
		CPUID => hex 'C000000',
		IA32_ARCH_CAPABILITIES => 2, #bit1 -- EIBRS
		SLE12SP4 => {
				"on" => "Mitigation: Indirect Branch Restricted Speculation.* IBPB: conditional,.* STIBP: conditional,.*", 
				"off" => ".*IBPB: disabled,.*STIBP: disabled", 
				"prctl" => (".*IBPB: conditional.*STIBP: conditional.*", "User space: Mitigation: STIBP via prctl"),
				"prctl,ibpb" => (".*IBPB: always-on.*STIBP: conditional.*", "mitigation: Enabling always-on Indirect Branch Prediction Barrier"),
				"seccomp" => (".*STIBP: conditional.*", "User space: Mitigation: STIBP via seccomp and prctl"),
				"seccomp,ibpb" => (".*IBPB: always-on.*STIBP: conditional.*", "User space: Mitigation: STIBP via seccomp and prctl"),
				"auto" => "Mitigation: Indirect Branch Restricted Speculation.* IBPB: conditional,.* STIBP: conditional,.*",
				},
		SLE12SP5 => {
				"on" => "Mitigation: Indirect Branch Restricted Speculation.* IBPB: conditional,.* STIBP: conditional,.*", 
				"off" => ".*IBPB: disabled,.*STIBP: disabled", 
				"prctl" => (".*IBPB: conditional.*STIBP: conditional.*", "User space: Mitigation: STIBP via prctl"),
				"prctl,ibpb" => (".*IBPB: always-on.*STIBP: conditional.*", "mitigation: Enabling always-on Indirect Branch Prediction Barrier"),
				"seccomp" => (".*STIBP: conditional.*", "User space: Mitigation: STIBP via seccomp and prctl"),
				"seccomp,ibpb" => (".*IBPB: always-on.*STIBP: conditional.*", "User space: Mitigation: STIBP via seccomp and prctl"),
				"auto" => "Mitigation: Indirect Branch Restricted Speculation.* IBPB: conditional,.* STIBP: conditional,.*",
				},
	},
	{
		name => "l1tf",
		CPUID => hex '10000000',
		IA32_ARCH_CAPABILITIES => 8, #bit3 --SKIP_L1TF_VMENTRY
		SLE12SP5 => {
				"full" => "Mitigation: Indirect Branch Restricted Speculation.* IBPB: conditional,.* STIBP: conditional,.*", 
				"full,force" => ".*IBPB: disabled,.*STIBP: disabled", 
				"flush" => (".*IBPB: conditional.*STIBP: conditional.*", "User space: Mitigation: STIBP via prctl"),
				"flush,nosmt" => (".*IBPB: always-on.*STIBP: conditional.*", "mitigation: Enabling always-on Indirect Branch Prediction Barrier"),
				"flush,nowarn" => (".*STIBP: conditional.*", "User space: Mitigation: STIBP via seccomp and prctl"),
				"off" => ("Mitigation: PTE Inversion; VMX: vulnerable", "User space: Mitigation: STIBP via seccomp and prctl"),
				},
	},
	{
		name => "spectre_v4",
		CPUID => hex '80000000',
		IA32_ARCH_CAPABILITIES => 16, #bit4 --SSB_NO 
		SLE12SP5 => {
				"full" => "Mitigation: Indirect Branch Restricted Speculation.* IBPB: conditional,.* STIBP: conditional,.*", 
				"full,force" => ".*IBPB: disabled,.*STIBP: disabled", 
				"flush" => (".*IBPB: conditional.*STIBP: conditional.*", "User space: Mitigation: STIBP via prctl"),
				"flush,nosmt" => (".*IBPB: always-on.*STIBP: conditional.*", "mitigation: Enabling always-on Indirect Branch Prediction Barrier"),
				"flush,nowarn" => (".*STIBP: conditional.*", "User space: Mitigation: STIBP via seccomp and prctl"),
				"off" => (".*IBPB: always-on.*STIBP: conditional.*", "User space: Mitigation: STIBP via seccomp and prctl"),
				},
	},
	{
		name => "mds",
		CPUID => hex '20000000',
		IA32_ARCH_CAPABILITIES => 32, #bit5 --MDS_NO
	},
);

sub new{

	my $class = shift;

	my $self = {
		'name' => shift,
		'CPUID' => shift,
		'IA32_ARCH_CAPABILITIES' => shift,
    		'parameter' => shift
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
					return 0; #Not Affected
				}else {
					return 1; #Affected
				}
			}
			return 1;
		}
	}
}

sub sysfs{
	my $self = shift;
	my $item;
	my $p;
	foreach $item (@mitigations_list) {
		if ($item->{'name'} eq $self->Name()) {
			for $p (keys %{$item->{'sysfs'}}) {
				print $syspath,$self->Name,"\n";
				print $item->{'sysfs'}->{$p},"\n";
			}
		}
	}
  return $item->{'sysfs'};
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
      for $p (keys %{$item->{'cmdline'}}) {
          print "cmdline ",$self->Name,"\n";
          print $item->{'cmdline'}->{$p},"\n";
      }
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
  if ( $ret ne 0 ) { 
    remove_grub_cmdline_settings($self->{'parameter'} . "=[a-z]*");
    bootloader_setup::grub_mkconfig();
    reboot_and_wait( $self, 150 );
    assert_script_run('grep -v "' . $self->{'parameter'} . '=off" /proc/cmdline');
  }   
}

sub check_cpu_flags {
  my $self = shift;
  my $flag = shift;
  assert_script_run('cat /proc/cpuinfo');
  foreach $flag ($self->{'cpuflags'}) {
    assert_script_run('cat /proc/cpuinfo | grep "^flags.*' . $self->{'cpuflags'} .'.*"');
  }
}

sub check_sysfs {
  my $self = shift;
  my $value = shift; #the value of kernel parameter

  assert_script_run( 'cat ' . $syspath . $self->Name() );
  assert_script_run(
    'cat ' . $syspath . $self->Name() . '| grep ' . $self->sysfs()->{$value} );
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


sub add_parameter{
  my $self = shift;
  my $value = shift;
  add_grub_cmdline_settings($self->{'parameter'} .'='. $value);
  bootloader_setup::grub_mkconfig();
  reboot_and_wait( $self, 150 );
}

sub remove_parameter{
  my $self = shift;
  my $value = shift;
  remove_grub_cmdline_settings($self->{'parameter'} .'='. $value);
  bootloader_setup::grub_mkconfig();
  reboot_and_wait( $self, 150 );
}



1;

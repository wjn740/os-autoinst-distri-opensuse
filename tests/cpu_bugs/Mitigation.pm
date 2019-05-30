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

#use cpu_bugs;
#use base "consoletest";
##use bootloader_setup;
##use ipmi_backend_utils;
##use power_action_utils 'power_action';
use strict;
use warnings;
#use testapi;
#use utils;

package Mitigation;

my @mitigations_list = (
	{
		name => "meltdown",
		CPUID => hex '20000000',
		IA32_ARCH_CAPABILITIES => 1, #bit0 -- RDCL_NO
		SLE12SP4 => {
				"on" => "Mitigation: PTI", 
				"off" => "Vulnerable", 
				"auto" => "Mitigation: PTI",
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
		'IA32_ARCH_CAPABILITIES' => shift
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
					return 0;
				}else {
					return 1;
				}
			}
			return 1;
		}
	}
}


1;

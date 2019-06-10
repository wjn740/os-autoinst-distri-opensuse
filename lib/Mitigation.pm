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

sub new{

	my $class = shift;

	my $self = shift;

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
	return $self->{'CPUID'};
}

sub MSR {
	my ($self, $value) = @_;
	return $self->{'IA32_ARCH_CAPABILITIES'};
}

sub read_cpuid {
	my $self = shift;
	zypper_call("in cpuid");
	my $edx = hex script_output(
		"cpuid -1 -l 7 -s 0 -r | awk \'{print \$6}\' | awk -F \"=\" \'{print \$2}\' | tail -n1"
	);
	return $edx;
}

sub read_msr {
	my $self = shift;
	my $edx = script_output(
		"perl -e \'open(M,\"<\",\"/dev/cpu/0/msr\") and seek(M,0x10a,0) and read(M,\$_,8) and print\' | od -t u8 -A n"
	);
	return $edx;
}


sub show {
	my $self = shift;
	print $self->Name(),",";
	print $self->CPUID(),",";
	print $self->MSR(),"\n";
}

sub vulnerabilities {
	my $self = shift;
			if ($self->read_cpuid() & $self->CPUID()) {
				if ($self->read_msr() & $self->MSR()) {
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

sub sysfs{
	my ($self,$value) = @_;
	my $p;
			if (@_ == 2) {
  				return $self->{'sysfs'}->{$value};
			}
  			return $self->{'sysfs'};

}

sub dmesg{
	my $self = shift;
  my $p;
      for $p (keys %{$self->{'dmesg'}}) {
          print "dmesg ",$self->Name,"\n";
          print $self->{'dmesg'}->{$p},"\n";
      }
}

sub cmdline{
	my $self = shift;
	my $p;
	return $self->{'cmdline'};
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

  	remove_grub_cmdline_settings($self->{'parameter'} .'='. '[a-z]*');
}


1;

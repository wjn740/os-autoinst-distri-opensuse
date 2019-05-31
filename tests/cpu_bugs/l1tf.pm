# SUSE's openQA tests
#
# Copyright © 2009-2013 Bernhard M. Wiedemann
# Copyright © 2012-2018 SUSE LLC
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.

# Summary: CPU BUGS on Linux kernel check
# Maintainer: James Wang <jnwang@suse.com>

use strict;
use warnings;
#use FindBin;
#use lib $FindBin::Bin;

use base "consoletest";
use bootloader_setup;
use strict;
use testapi;
use utils;
use power_action_utils 'power_action';

use Mitigation;


sub run {
  my $obj = new Mitigation("l1tf", "", 0);

  $obj->Name("l1tf");

  $obj->load_msr();
  $obj->load_cpuid();

}

sub test_flags {
    return { milestone => 1, fatal => 0 };
}

sub post_fail_hook {
    my ($self) = @_;
    select_console 'root-console';
    assert_script_run(
        "md /tmp/upload; cp ". $Mitigation::syspath . "* /tmp/upload; cp /proc/cmdline /tmp/upload; lscpu >/tmp/upload/cpuinfo; tar -jcvf /tmp/upload.tar.bz2 /tmp/upload"
    );
    remove_grub_cmdline_settings('l1tf=[a-z,]*');
    grub_mkconfig;
    upload_logs '/tmp/upload.tar.bz2';
    $self->SUPER::post_fail_hook;
}

1;

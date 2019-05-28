# SUSE's openQA tests
#
# Copyright © 2009-2013 Bernhard M. Wiedemann
# Copyright © 2012-2018 SUSE LLC
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.

# Summary: library of CPU BUGS on Linux kernel check
# Maintainer: James Wang <jnwang@suse.com>

use base "consoletest";
use bootloader_setup;
use strict;
use testapi;
use utils;
use power_action_utils 'power_action';
use ipmi_backend_utils;

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

1;

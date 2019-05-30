
use strict;
use warnings;
use FindBin;
use lib $FindBin::Bin;

use Mitigation;

my $obj = new Mitigation("PTI", "", 1);
print "$obj->{'IA32_ARCH_CAPABILITIES'}\n";
print "$obj->{'CPUID'}\n";

$obj->Name("pti");
$obj->CPUID(hex 'ffff0000');
$obj->MSR(1);
$obj->show();

print $obj->vulnerabilities();



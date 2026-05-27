control 'SV-281009' do
  title 'RHEL 10 must enable FIPS mode.'
  desc <<~DESC
    Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government because this provides assurance they have been tested and validated.

    Satisfies: SRG-OS-000033-GPOS-00014, SRG-OS-000125-GPOS-00065, SRG-OS-000250-GPOS-00093, SRG-OS-000393-GPOS-00173, SRG-OS-000394-GPOS-00174, SRG-OS-000396-GPOS-00176, SRG-OS-000423-GPOS-00187, SRG-OS-000478-GPOS-00223
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is in FIPS mode with the following command:

    $ cat /proc/sys/crypto/fips_enabled
    1

    If the command does not return "1", this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to implement FIPS mode.

    If this check fails on an installed system, it is a permanent finding until the system is reinstalled with "fips=1" during installation.

    Red Hat 10 does not support switching to strict FIPS mode after installation.
  FIXTEXT
  impact 0.7
  tag check_id: 'M'
  tag severity: 'high'
  tag gid: 'V-281009'
  tag rid: 'SV-281009r1184724_rule'
  tag stig_id: 'RHEL-10-000500'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-85475r1184723_fix'
  tag cci: ['CCI-000068', 'CCI-000877', 'CCI-001453', 'CCI-002890', 'CCI-003123', 'CCI-002450', 'CCI-002418']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("cat /proc/sys/crypto/fips_enabled") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end

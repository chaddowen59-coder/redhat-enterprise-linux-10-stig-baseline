control 'SV-281271' do
  title 'RHEL 10 must not have a "shosts.equiv" file on the system.'
  desc <<~DESC
    The "shosts.equiv" files are used to configure host-based authentication for the system via Secure Shell (SSH). Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 does not have a "shosts.equiv" file on the system with the following command:

    $ sudo find / -name shosts.equiv

    If a "shosts.equiv" file is found, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to not have a "shosts.equiv" file on the system.

    Remove any found "shosts.equiv" files from the system:

    $ sudo rm /[path]/[to]/[file]/shosts.equiv
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281271'
  tag rid: 'SV-281271r1197244_rule'
  tag stig_id: 'RHEL-10-700680'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85737r1197243_fix'
  tag cci: ['CCI-000213']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("find / -name shosts.equiv") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end

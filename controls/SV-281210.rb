control 'SV-281210' do
  title 'RHEL 10 must use the invoking user\'s password for privilege escalation when using "sudo".'
  desc <<~DESC
    If the "rootpw", "targetpw", or "runaspw" flags are defined and not disabled, by default the operating system will prompt the invoking user for the "root" user password.
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 sudoers security policy is configured to use the invoking user's password for privilege escalation with the following command:

    $ sudo grep -irE '(!rootpw|!targetpw|!runaspw)' /etc/sudoers /etc/sudoers.d/ | grep -v '#'
    /etc/sudoers:Defaults !targetpw
    /etc/sudoers:Defaults !rootpw
    /etc/sudoers:Defaults !runaspw

    If no results are returned, this is a finding.

    If results are returned from more than one file location, this is a finding.

    If "Defaults !targetpw" is not defined, this is a finding.

    If "Defaults !rootpw" is not defined, this is a finding.

    If "Defaults !runaspw" is not defined, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to use the invoking user's password for privilege escalation when using "sudo".

    Define the following in the Defaults section of the /etc/sudoers file or a single configuration file in the /etc/sudoers.d/ directory:

    Defaults !targetpw
    Defaults !rootpw
    Defaults !runaspw
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281210'
  tag rid: 'SV-281210r1166582_rule'
  tag stig_id: 'RHEL-10-600550'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-85676r1166581_fix'
  tag cci: ['CCI-002038']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe file('/etc/sudoers') do
    it { should exist }
    its('content') { should match(/(!rootpw|!targetpw|!runaspw)/i) }
  end
end

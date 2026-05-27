control 'SV-281208' do
  title 'RHEL 10 must require users to reauthenticate for privilege escalation.'
  desc <<~DESC
    Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

    When operating systems provide the capability to escalate a functional capability, it is critical that the user reauthenticate.

    Satisfies: SRG-OS-000373-GPOS-00156, SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00158
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 "/etc/sudoers" has no occurrences of "!authenticate" with the following command:

    $ sudo grep -ir '!authenticate' /etc/sudoers /etc/sudoers.d/

    If any occurrences of "!authenticate" are returned, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to not allow users to execute privileged actions without authenticating.

    Remove any occurrence of "!authenticate" found in the "/etc/sudoers" file or files in the "/etc/sudoers.d" directory:

    $ sudo sed -i '/\!authenticate/ s/^/# /g' /etc/sudoers /etc/sudoers.d/*
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281208'
  tag rid: 'SV-281208r1166576_rule'
  tag stig_id: 'RHEL-10-600530'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-85674r1166575_fix'
  tag cci: ['CCI-002038']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe file('/etc/sudoers') do
    it { should exist }
    its('content') { should match(/!authenticate/i) }
  end
end

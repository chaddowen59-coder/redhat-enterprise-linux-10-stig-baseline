control 'SV-281211' do
  title 'RHEL 10 must require users to provide a password for privilege escalation.'
  desc <<~DESC
    Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

    When operating systems provide the capability to escalate a functional capability, it is critical that the user reauthenticate.

    Satisfies: SRG-OS-000373-GPOS-00156, SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00158
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 has no occurrences of "NOPASSWD" in "/etc/sudoers" with the following command:

    $ sudo grep -ir nopasswd /etc/sudoers /etc/sudoers.d/ | grep -v '#'

    If any occurrences of "NOPASSWD" are returned from the command and have not been documented with the information system security officer as an organizationally defined administrative group using multifactor authentication, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to not allow users to execute privileged actions without authenticating with a password.

    Remove any occurrence of "NOPASSWD" found in the "/etc/sudoers" file or files in the "/etc/sudoers.d" directory:

    $ sudo find /etc/sudoers /etc/sudoers.d -type f -exec sed -i '/NOPASSWD/ s/^/# /g' {} \;
  FIXTEXT
  impact 0.7
  tag check_id: 'M'
  tag severity: 'high'
  tag gid: 'V-281211'
  tag rid: 'SV-281211r1166585_rule'
  tag stig_id: 'RHEL-10-600560'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-85677r1166584_fix'
  tag cci: ['CCI-002038']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep -ir nopasswd /etc/sudoers /etc/sudoers.d/ | grep -v '#'") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end

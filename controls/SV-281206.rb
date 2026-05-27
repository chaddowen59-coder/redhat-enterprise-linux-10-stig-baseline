control 'SV-281206' do
  title 'RHEL 10 must be configured to not bypass password requirements for privilege escalation.'
  desc <<~DESC
    Without reauthentication, users may access resources or perform tasks for which they do not have authorization. When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.

    Satisfies: SRG-OS-000373-GPOS-00156, SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00158
  DESC
  desc 'check', <<~CHECKTEXT
    Verify RHEL 10 is not configured to bypass password requirements for privilege escalation with the following command:

    $ sudo grep pam_succeed_if /etc/pam.d/sudo

    If any occurrences of "pam_succeed_if" are returned, this is a finding.
  CHECKTEXT
  desc 'fix', <<~FIXTEXT
    Configure RHEL 10 to require users to supply a password for privilege escalation.

    Remove any occurrences of " pam_succeed_if " in the "/etc/pam.d/sudo" file.
  FIXTEXT
  impact 0.5
  tag check_id: 'M'
  tag severity: 'medium'
  tag gid: 'V-281206'
  tag rid: 'SV-281206r1166570_rule'
  tag stig_id: 'RHEL-10-600510'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-85672r1166569_fix'
  tag cci: ['CCI-002038']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe command("grep pam_succeed_if /etc/pam.d/sudo") do
    its('exit_status') { should cmp 0 }
    its('stdout') { should_not be_empty }
  end
end
